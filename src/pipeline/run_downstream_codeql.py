from __future__ import annotations
import json, os
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from src.tools.codeql_runner import codeql_db_create, codeql_query_run, codeql_bqrs_decode_csv
from src.cal_graph_builder.from_codeql_csv import convert_codeql_csv_to_callgraph


def _configure_console_utf8() -> None:
    """
    Windows PowerShell / CMD 默认可能是 gbk，打印特殊符号（如 ✓/✗）会触发 UnicodeEncodeError。
    这里尽量将 stdout/stderr 切到 UTF-8，避免控制台编码问题。
    """
    try:
        import sys

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _auto_detect_codeql(default_arg: str) -> str:
    """
    若用户未显式指定 --codeql（仍为 'codeql'），则尝试自动发现项目内 tools/codeql 的安装位置。
    """
    if default_arg and default_arg != "codeql":
        return default_arg

    # 常见安装位置（由 scripts/download_codeql_cli.py 解压出来）
    candidates = [
        Path("tools/codeql/codeql/codeql.exe"),
        Path("tools/codeql/codeql.exe"),
        Path("tools/codeql/codeql/codeql"),
        Path("tools/codeql/codeql"),
    ]
    for c in candidates:
        p = c.resolve()
        if p.is_file():
            return str(p)

    # 兜底：保持原样，让后续的 version 检查给出提示
    return default_arg

def detect_build_system(project_dir: Path) -> Tuple[str, str]:
    """return (system, build_cmd)"""
    if (project_dir / "pom.xml").is_file():
        project_hint = str(project_dir).replace("\\", "/").lower()
        if project_hint.endswith("/cve-2020-13956/downstream/share"):
            # share 的 war 聚合模块在 CodeQL tracing 下易因旧插件/overlay 失败；
            # 这里先聚焦可编译的核心模块，保证调用图可产出。
            cmd = (
                "mvn "
                "-DskipTests "
                "-Dspotbugs.skip=true -Dcheckstyle.skip=true "
                "-Dlicense.skip=true -Dmaven.javadoc.skip=true -Djacoco.skip=true "
                "-pl share-services,web-framework-commons,share-encryption -am "
                "clean test-compile"
            )
            return "maven", cmd

        # snowflake-jdbc 在拉取依赖时会命中内部 nexus，当前环境下证书域名校验不匹配导致失败。
        # 这里给该项目的 Maven 构建加“宽松 SSL”以便依赖能继续下载（实验目的，避免阻断分析）。
        if "snowflake-jdbc-vuln-4.5.11" in project_hint:
            cmd = (
                "mvn "
                "-DskipTests "
                "-Dspotbugs.skip=true -Dcheckstyle.skip=true "
                "-Dlicense.skip=true -Dmaven.javadoc.skip=true -Djacoco.skip=true "
                "-Dmaven.wagon.http.ssl.insecure=true -Dmaven.wagon.http.ssl.allowall=true "
                "-Dmaven.war.cache=false "
                "clean test-compile"
            )
            return "maven", cmd
        # CodeQL Java extractor 需要在构建过程中“看到”实际的编译（javac）。
        # 很多项目在二次运行时会出现 "Nothing to compile"，导致 CodeQL 报：
        #   could not process any of it / no source code seen during build
        # 因此这里强制 clean，保证会触发重新编译；并尽量跳过与分析无关的插件以加速。
        cmd = (
            "mvn "
            "-DskipTests "
            "-Dspotbugs.skip=true -Dcheckstyle.skip=true "
            "-Dlicense.skip=true -Dmaven.javadoc.skip=true -Djacoco.skip=true "
            "-Dmaven.war.cache=false "
            "clean test-compile"
        )
        return "maven", cmd
    if (project_dir / "build.gradle").is_file() or (project_dir / "build.gradle.kts").is_file():
        cmd = "gradle --no-daemon -x test classes"
        return "gradle", cmd
    return "unknown", ""

def write_maven_settings(settings_path: Path, local_repo: Path) -> None:
    """
    Maven 本地仓库路径推荐通过 settings.xml 的 <localRepository> 配置。
    """
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        f"""<settings>
  <localRepository>{local_repo.as_posix()}</localRepository>
  <mirrors>
    <!--
      代码采集环境可能无法访问/无法校验证书的内部仓库。
      为了保证样本能够继续构建/建库，这里将所有远程仓库都镜像到 Maven Central。
    -->
    <mirror>
      <id>force-maven-central</id>
      <mirrorOf>*</mirrorOf>
      <url>https://repo.maven.apache.org/maven2</url>
    </mirror>
  </mirrors>
</settings>
""",
        encoding="utf-8",
    )

def run_one_sample(
    sample_dir: Path,
    manifest_resolved: Dict[str, Any],
    codeql_bin: str,
    cache_root: Path,
    out_root: Path,
    timeout_db_create_sec: int = 1800,  # 30min
    timeout_query_sec: int = 900,       # 15min
) -> Dict[str, Any]:
    """
    输入：单样本 resolved manifest（你 dataset_handler.py 已经能生成，见你文件）。
    输出：在 manifest_resolved 上追加 codeql 状态与输出路径。
    """
    ds_list = manifest_resolved.get("downstream") or []
    if not ds_list:
        result = dict(manifest_resolved)
        result.setdefault("analysis", {})["build_status"] = "build_failed"
        result["analysis"]["reason"] = "manifest 中缺少 downstream 字段"
        return result

    ds = ds_list[0]
    src_dir = ds.get("src_dir_resolved", "")
    if not src_dir:
        result = dict(manifest_resolved)
        result.setdefault("analysis", {})["build_status"] = "build_failed"
        result["analysis"]["reason"] = "downstream 中缺少 src_dir_resolved 字段"
        return result

    project_dir = Path(src_dir).resolve()
    if not project_dir.exists():
        result = dict(manifest_resolved)
        result.setdefault("analysis", {})["build_status"] = "build_failed"
        result["analysis"]["reason"] = f"项目目录不存在: {project_dir}"
        return result

    result = dict(manifest_resolved)

    analysis_dir = out_root / sample_dir.name / "analysis"
    logs_dir = out_root / sample_dir.name / "logs"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    system, build_cmd = detect_build_system(project_dir)
    result.setdefault("analysis", {})["build_system"] = system
    result["analysis"]["build_cmd"] = build_cmd

    if system == "unknown" or not build_cmd:
        result["analysis"]["build_status"] = "build_failed"
        result["analysis"]["reason"] = "unknown build system (no pom.xml / build.gradle)"
        return result

    # --- cache settings ---
    env = os.environ.copy()

    # Maven cache: 用 settings.xml 指定 localRepository，集中复用。
    m2_repo = cache_root / "m2_repository"
    gradle_home = cache_root / "gradle_user_home"

    if system == "maven":
        settings_xml = cache_root / "maven_settings.xml"
        write_maven_settings(settings_xml, m2_repo)
        # 强制使用该 settings，确保所有样本复用同一个 repo
        build_cmd = f'{build_cmd} -s "{settings_xml.as_posix()}"'
        result["analysis"]["maven_settings"] = str(settings_xml)
        result["analysis"]["maven_local_repo"] = str(m2_repo)

    if system == "gradle":
        # Gradle cache 通过 GRADLE_USER_HOME 统一到共享目录。
        env["GRADLE_USER_HOME"] = str(gradle_home)
        result["analysis"]["gradle_user_home"] = str(gradle_home)

    # --- CodeQL database create (downstream only) ---
    db_dir = out_root / sample_dir.name / "codeql_db"
    create_log = logs_dir / "codeql_db_create.log"
    r = codeql_db_create(
        codeql_bin=codeql_bin,
        db_dir=db_dir,
        project_dir=project_dir,
        build_cmd=build_cmd,
        env=env,
        timeout_sec=timeout_db_create_sec,
        log_path=create_log,
    )
    if not r.ok:
        result["analysis"]["build_status"] = "build_failed"
        result["analysis"]["codeql_db_create_log"] = str(create_log)
        result["analysis"]["codeql_db_dir"] = str(db_dir)
        result["analysis"]["returncode"] = r.returncode
        return result

    result["analysis"]["build_status"] = "ok"
    result["analysis"]["codeql_db_dir"] = str(db_dir)

    # --- Call edges query => downstream_callgraph.csv/.dot ---
    ql_call_edges = Path("queries/java/call_edges.ql").resolve()
    if not ql_call_edges.exists():
        result["analysis"]["callgraph_status"] = "failed"
        result["analysis"]["callgraph_error"] = f"CodeQL 查询文件不存在: {ql_call_edges}"
        return result

    bqrs = analysis_dir / "call_edges.bqrs"
    csv_out = analysis_dir / "downstream_callgraph_raw.csv"
    qlog = logs_dir / "codeql_call_edges.log"
    
    r1 = codeql_query_run(codeql_bin, db_dir, ql_call_edges, bqrs, env, timeout_query_sec, qlog)
    if not r1.ok:
        result["analysis"]["callgraph_status"] = "failed"
        result["analysis"]["callgraph_log"] = str(qlog)
        result["analysis"]["callgraph_error"] = f"CodeQL 查询失败，返回码: {r1.returncode}"
        if r1.stderr:
            result["analysis"]["callgraph_stderr"] = r1.stderr[:500]  # 限制长度
        return result

    r2 = codeql_bqrs_decode_csv(codeql_bin, bqrs, csv_out, env, timeout_query_sec, logs_dir / "codeql_bqrs_decode.log")
    if not r2.ok:
        result["analysis"]["callgraph_status"] = "failed"
        result["analysis"]["callgraph_error"] = f"BQRS 解码失败，返回码: {r2.returncode}"
        if r2.stderr:
            result["analysis"]["callgraph_stderr"] = r2.stderr[:500]
        return result

    # --- Call edges detailed query => downstream_callgraph_detailed.csv ---
    # 详细输出拆成两份：callsite（每个调用点一行）+ args（每个实参一行）
    ql_call_sites = Path("queries/java/call_sites_detailed.ql").resolve()
    ql_call_args = Path("queries/java/call_edges_detailed.ql").resolve()

    if ql_call_sites.exists():
        bqrs_sites = analysis_dir / "call_sites_detailed.bqrs"
        csv_sites_out = analysis_dir / "downstream_callsites_detailed.csv"
        qlog_sites = logs_dir / "codeql_call_sites_detailed.log"
        r_sites = codeql_query_run(codeql_bin, db_dir, ql_call_sites, bqrs_sites, env, timeout_query_sec, qlog_sites)
        if r_sites.ok:
            r_sites_dec = codeql_bqrs_decode_csv(
                codeql_bin, bqrs_sites, csv_sites_out, env, timeout_query_sec, logs_dir / "codeql_bqrs_decode_sites.log"
            )
            if r_sites_dec.ok:
                result["analysis"]["downstream_callsites_detailed_csv"] = str(csv_sites_out)
            else:
                result["analysis"]["callgraph_detailed_status"] = "sites_decode_failed"
        else:
            result["analysis"]["callgraph_detailed_status"] = "sites_query_failed"

    if ql_call_args.exists():
        bqrs_args = analysis_dir / "call_args_detailed.bqrs"
        csv_args_out = analysis_dir / "downstream_callargs_detailed.csv"
        qlog_args = logs_dir / "codeql_call_args_detailed.log"
        r_args = codeql_query_run(codeql_bin, db_dir, ql_call_args, bqrs_args, env, timeout_query_sec, qlog_args)
        if r_args.ok:
            r_args_dec = codeql_bqrs_decode_csv(
                codeql_bin, bqrs_args, csv_args_out, env, timeout_query_sec, logs_dir / "codeql_bqrs_decode_args.log"
            )
            if r_args_dec.ok:
                result["analysis"]["downstream_callargs_detailed_csv"] = str(csv_args_out)
            else:
                result["analysis"]["callgraph_detailed_status"] = "args_decode_failed"
        else:
            result["analysis"]["callgraph_detailed_status"] = "args_query_failed"

    # --- 转换为标准格式：downstream_callgraph.csv 和 downstream_callgraph.dot ---
    try:
        standard_csv, standard_dot = convert_codeql_csv_to_callgraph(
            codeql_csv_path=csv_out,
            output_dir=analysis_dir,
            prefix="downstream",
        )
        result["analysis"]["callgraph_status"] = "ok"
        result["analysis"]["downstream_callgraph_raw_csv"] = str(csv_out)
        result["analysis"]["downstream_callgraph_csv"] = str(standard_csv)
        result["analysis"]["downstream_callgraph_dot"] = str(standard_dot)
    except Exception as e:
        result["analysis"]["callgraph_status"] = "conversion_failed"
        result["analysis"]["callgraph_conversion_error"] = str(e)
        result["analysis"]["downstream_callgraph_raw_csv"] = str(csv_out)

    return result

def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="运行 CodeQL 分析流程",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("dataset_processed_manifest", help="processed/manifest_resolved.json")
    ap.add_argument("--out", default="output", help="output root dir")
    ap.add_argument("--cache", default="cache", help="cache root dir (.m2/.gradle)")
    ap.add_argument("--codeql", default="codeql", help="codeql binary path")
    args = ap.parse_args()

    _configure_console_utf8()
    args.codeql = _auto_detect_codeql(args.codeql)

    print("=" * 60)
    print("CodeQL 分析流程")
    print("=" * 60)

    # 检查 manifest 文件
    manifest_path = Path(args.dataset_processed_manifest).resolve()
    if not manifest_path.exists():
        print(f"[ERROR] Manifest 文件不存在: {manifest_path}")
        print("  请先运行 dataset_handler.py 生成 manifest_resolved.json")
        return 1
    print(f"[OK] Manifest 文件: {manifest_path}")

    # 检查 CodeQL
    import subprocess
    try:
        result = subprocess.run(
            [args.codeql, "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"[ERROR] CodeQL 不可用: {args.codeql}")
            if result.stderr:
                print(f"  输出: {result.stderr}")
            return 1
        print(f"[OK] CodeQL: {args.codeql} ({result.stdout.strip()})")
    except FileNotFoundError:
        print(f"[ERROR] 未找到 CodeQL: {args.codeql}")
        print("  请确保 CodeQL 已安装并在 PATH 中，或使用 --codeql 指定完整路径")
        return 1
    except Exception as e:
        print(f"[ERROR] 检查 CodeQL 时出错: {e}")
        return 1

    # 检查查询文件
    ql_file = Path("queries/java/call_edges.ql").resolve()
    if not ql_file.exists():
        print(f"[ERROR] CodeQL 查询文件不存在: {ql_file}")
        print("  请确保 queries/java/call_edges.ql 存在")
        return 1
    print(f"[OK] CodeQL 查询文件: {ql_file}")

    out_root = Path(args.out).resolve()
    cache_root = Path(args.cache).resolve()
    cache_root.mkdir(parents=True, exist_ok=True)
    out_root.mkdir(parents=True, exist_ok=True)
    print(f"[OK] 输出目录: {out_root}")
    print(f"[OK] 缓存目录: {cache_root}")

    # 读取 manifest
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[ERROR] Manifest 文件格式错误: {e}")
        return 1
    except Exception as e:
        print(f"[ERROR] 读取 manifest 文件失败: {e}")
        return 1

    samples = data.get("samples") or []
    if not samples:
        print("[WARN] Manifest 中没有样本数据")
        return 0

    print(f"\n找到 {len(samples)} 个样本")
    print("-" * 60)

    new_samples = []
    success_count = 0
    failed_count = 0
    skipped_count = 0

    for idx, s in enumerate(samples, 1):
        sample_id = s.get("id") or s.get("sample_dir") or f"sample_{idx}"
        print(f"\n[{idx}/{len(samples)}] 处理样本: {sample_id}")

        sample_dir = Path(s.get("sample_dir") or s.get("sample_root") or s.get("id") or "")
        if not sample_dir or not str(sample_dir):
            print(f"  ⚠ 跳过: 缺少 sample_dir 字段")
            new_samples.append(s)
            skipped_count += 1
            continue

        sample_dir = Path(sample_dir)
        if not sample_dir.exists():
            print(f"  ⚠ 跳过: 样本目录不存在: {sample_dir}")
            new_samples.append(s)
            skipped_count += 1
            continue

        try:
            result = run_one_sample(
                sample_dir=sample_dir,
                manifest_resolved=s,
                codeql_bin=args.codeql,
                cache_root=cache_root,
                out_root=out_root,
            )
            new_samples.append(result)

            # 检查结果状态
            analysis = result.get("analysis", {})
            build_status = analysis.get("build_status", "unknown")
            callgraph_status = analysis.get("callgraph_status", "unknown")

            if build_status == "ok" and callgraph_status == "ok":
                print("  [OK] 成功: 构建和调用图生成完成")
                success_count += 1
            elif build_status == "build_failed":
                reason = analysis.get("reason", "未知原因")
                print(f"  [FAIL] 构建失败 - {reason}")
                if analysis.get("codeql_db_create_log"):
                    print(f"    日志: {analysis['codeql_db_create_log']}")
                failed_count += 1
            elif callgraph_status == "failed":
                print("  [FAIL] 调用图生成失败")
                if analysis.get("callgraph_log"):
                    print(f"    日志: {analysis['callgraph_log']}")
                failed_count += 1
            elif callgraph_status == "conversion_failed":
                print("  [WARN] CodeQL 查询成功，但转换失败")
                print(f"    错误: {analysis.get('callgraph_conversion_error', '未知')}")
                failed_count += 1
            else:
                print(f"  [WARN] 未知状态: build_status={build_status}, callgraph_status={callgraph_status}")
                failed_count += 1

        except Exception as e:
            print(f"  [ERROR] 异常: {e}")
            import traceback
            traceback.print_exc()
            failed_count += 1
            # 保留原始数据并添加错误信息
            error_result = dict(s)
            error_result.setdefault("analysis", {})["error"] = str(e)
            new_samples.append(error_result)

    # 保存结果
    out_manifest = out_root / "manifest_with_codeql.json"
    try:
        out_manifest.write_text(
            json.dumps({"samples": new_samples}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print("\n" + "=" * 60)
        print("分析完成")
        print("=" * 60)
        print(f"成功: {success_count}")
        print(f"失败: {failed_count}")
        print(f"跳过: {skipped_count}")
        print(f"\n结果已保存到: {out_manifest}")
        return 0
    except Exception as e:
        print(f"\n[ERROR] 保存结果失败: {e}")
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
