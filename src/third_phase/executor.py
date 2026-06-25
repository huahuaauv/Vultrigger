from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from src.third_phase.models import RunSummary, TestTask

TEST_REL = Path("src/test/java/auto/gen/pov/ThirdPhasePOVTest.java")
TEMPLATE_NAME = "test_class_template.java"


def _template_dir() -> Path:
    return Path(__file__).resolve().parent / "templates"


def _read_template() -> str:
    return (_template_dir() / TEMPLATE_NAME).read_text(encoding="utf-8")


def clean_generated_tests(project_root: Path) -> None:
    root = project_root.resolve()
    targets = [
        root / "src/test/java/auto/gen/pov/ThirdPhasePOVTest.java",
        root / "src/test/java/auto/gen/pov",
        root / "target",
        root / "surefire-reports",
        root / "target/surefire-reports",
        root / "target/test-classes/auto/gen/pov",
    ]
    for t in targets:
        if t.is_file():
            t.unlink(missing_ok=True)  # type: ignore[arg-type]
        elif t.is_dir():
            shutil.rmtree(t, ignore_errors=True)


def render_test_class(method_body: str) -> str:
    tpl = _read_template()
    return tpl.replace("{{METHOD_BODY}}", method_body.rstrip() + "\n")


def write_generated_test(project_root: Path, method_body: str) -> Path:
    out = project_root.resolve() / TEST_REL
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_test_class(method_body), encoding="utf-8")
    return out


def _java_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("\"", "\\\"")


def _detect_bridge_kind(line: str) -> str:
    s = line.strip()
    if ".setURI(" in s or ".setURI (" in s:
        return "setURI"
    if re.search(r"\bnew\s+HttpGet\s*\(", s):
        return "httpget_ctor"
    if re.search(r"\bnew\s+HttpPost\s*\(", s):
        return "httppost_ctor"
    if re.search(r"\.\s*execute\s*\(", s):
        return "execute"
    return "unknown"


def _inject_seturi_block(
    lines: list[str],
    line_idx: int,
    path_id: str,
    bridge_file: str,
    bridge_line: int,
    bridge_arg: str,
    payload_substr: str,
) -> tuple[list[str], bool]:
    line = lines[line_idx]
    indent = line[: len(line) - len(line.lstrip())]
    # 参数中可含嵌套括号，例如 builder.build()；不能用 [^)]+
    m = re.search(r"\.setURI\s*\(\s*(.*)\)\s*;\s*$", line.rstrip())
    if not m:
        return lines, False
    arg = m.group(1).strip()
    bid = _java_escape(path_id)
    bfile = _java_escape(bridge_file)
    barg = _java_escape(bridge_arg)
    psub = _java_escape(payload_substr)
    replacement = (
        f"{indent}{{\n"
        f"{indent}  java.net.URI __autoPovUriForBridge = {arg};\n"
        f'{indent}  System.out.println("[AUTO-POV] HIT_BRIDGE_POINT path_id=" + "{bid}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_FILE=" + "{bfile}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_LINE=" + {int(bridge_line)});\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_ARG=" + "{barg}");\n'
        f'{indent}  System.out.println("[AUTO-POV] REQUEST_URI=" + String.valueOf(__autoPovUriForBridge));\n'
        f"{indent}  boolean __autoPovPayloadHit = String.valueOf(__autoPovUriForBridge).contains(\"{psub}\");\n"
        f'{indent}  System.out.println("[AUTO-POV] PAYLOAD_OBSERVED=" + __autoPovPayloadHit);\n'
        f"{indent}  httpRequest.setURI(__autoPovUriForBridge);\n"
        f"{indent}}}\n"
    )
    out = lines[:line_idx] + [replacement.rstrip("\n")] + lines[line_idx + 1 :]
    return out, True


def _inject_execute_before(
    lines: list[str],
    line_idx: int,
    path_id: str,
    bridge_file: str,
    bridge_line: int,
    bridge_arg: str,
    payload_substr: str,
) -> tuple[list[str], bool]:
    line = lines[line_idx]
    indent = line[: len(line) - len(line.lstrip())]
    bid = _java_escape(path_id)
    bfile = _java_escape(bridge_file)
    barg = _java_escape(bridge_arg)
    psub = _java_escape(payload_substr)
    probe = (
        f"{indent}{{\n"
        f'{indent}  System.out.println("[AUTO-POV] HIT_BRIDGE_POINT path_id=" + "{bid}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_FILE=" + "{bfile}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_LINE=" + {int(bridge_line)});\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_ARG=" + "{barg}");\n'
        f"{indent}  try {{\n"
        f"{indent}    if (httpRequest instanceof org.apache.http.client.methods.HttpUriRequest) {{\n"
        f"{indent}      java.net.URI __u = ((org.apache.http.client.methods.HttpUriRequest) httpRequest).getURI();\n"
        f'{indent}      System.out.println("[AUTO-POV] REQUEST_URI=" + String.valueOf(__u));\n'
        f"{indent}      System.out.println(\"[AUTO-POV] PAYLOAD_OBSERVED=\" + String.valueOf(__u).contains(\"{psub}\"));\n"
        f"{indent}    }} else {{\n"
        f'{indent}      System.out.println("[AUTO-POV] REQUEST_URI=" + String.valueOf(httpRequest));\n'
        f"{indent}      System.out.println(\"[AUTO-POV] PAYLOAD_OBSERVED=\" + String.valueOf(httpRequest).contains(\"{psub}\"));\n"
        f"{indent}    }}\n"
        f"{indent}  }} catch (Exception __autoPovEx) {{\n"
        f'{indent}    System.out.println("[AUTO-POV] REQUEST_URI=<error>");\n'
        f'{indent}    System.out.println("[AUTO-POV] PAYLOAD_OBSERVED=false");\n'
        f"{indent}  }}\n"
        f"{indent}}}\n"
    )
    out = lines[:line_idx] + [probe.rstrip("\n"), line] + lines[line_idx + 1 :]
    return out, True


def _inject_httpget_after(
    lines: list[str],
    line_idx: int,
    path_id: str,
    bridge_file: str,
    bridge_line: int,
    bridge_arg: str,
    payload_substr: str,
) -> tuple[list[str], bool]:
    line = lines[line_idx]
    indent = line[: len(line) - len(line.lstrip())]
    m = re.search(
        r"(?:final\s+)?(?:org\.apache\.http\.client\.methods\.)?HttpGet\s+(\w+)\s*=\s*new\s+HttpGet\s*\(",
        line,
    )
    var = m.group(1) if m else "autoPovGet"
    bid = _java_escape(path_id)
    bfile = _java_escape(bridge_file)
    barg = _java_escape(bridge_arg)
    psub = _java_escape(payload_substr)
    probe = (
        f"{indent}{{\n"
        f'{indent}  System.out.println("[AUTO-POV] HIT_BRIDGE_POINT path_id=" + "{bid}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_FILE=" + "{bfile}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_LINE=" + {int(bridge_line)});\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_ARG=" + "{barg}");\n'
        f"{indent}  try {{\n"
        f"{indent}    java.net.URI __u = {var}.getURI();\n"
        f'{indent}    System.out.println("[AUTO-POV] REQUEST_URI=" + String.valueOf(__u));\n'
        f"{indent}    System.out.println(\"[AUTO-POV] PAYLOAD_OBSERVED=\" + String.valueOf(__u).contains(\"{psub}\"));\n"
        f"{indent}  }} catch (Exception __e) {{\n"
        f'{indent}    System.out.println("[AUTO-POV] REQUEST_URI=<error>");\n'
        f'{indent}    System.out.println("[AUTO-POV] PAYLOAD_OBSERVED=false");\n'
        f"{indent}  }}\n"
        f"{indent}}}\n"
    )
    out = lines[: line_idx + 1] + [probe.rstrip("\n")] + lines[line_idx + 1 :]
    return out, True


def _inject_httppost_after(
    lines: list[str],
    line_idx: int,
    path_id: str,
    bridge_file: str,
    bridge_line: int,
    bridge_arg: str,
    payload_substr: str,
) -> tuple[list[str], bool]:
    line = lines[line_idx]
    indent = line[: len(line) - len(line.lstrip())]
    m = re.search(
        r"(?:final\s+)?(?:org\.apache\.http\.client\.methods\.)?HttpPost\s+(\w+)\s*=\s*new\s+HttpPost\s*\(",
        line,
    )
    var = m.group(1) if m else "autoPovPost"
    bid = _java_escape(path_id)
    bfile = _java_escape(bridge_file)
    barg = _java_escape(bridge_arg)
    psub = _java_escape(payload_substr)
    probe = (
        f"{indent}{{\n"
        f'{indent}  System.out.println("[AUTO-POV] HIT_BRIDGE_POINT path_id=" + "{bid}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_FILE=" + "{bfile}");\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_LINE=" + {int(bridge_line)});\n'
        f'{indent}  System.out.println("[AUTO-POV] BRIDGE_ARG=" + "{barg}");\n'
        f"{indent}  try {{\n"
        f"{indent}    java.net.URI __u = {var}.getURI();\n"
        f'{indent}    System.out.println("[AUTO-POV] REQUEST_URI=" + String.valueOf(__u));\n'
        f"{indent}    System.out.println(\"[AUTO-POV] PAYLOAD_OBSERVED=\" + String.valueOf(__u).contains(\"{psub}\"));\n"
        f"{indent}  }} catch (Exception __e) {{\n"
        f'{indent}    System.out.println("[AUTO-POV] REQUEST_URI=<error>");\n'
        f'{indent}    System.out.println("[AUTO-POV] PAYLOAD_OBSERVED=false");\n'
        f"{indent}  }}\n"
        f"{indent}}}\n"
    )
    out = lines[: line_idx + 1] + [probe.rstrip("\n")] + lines[line_idx + 1 :]
    return out, True


def instrument_bridge_file(
    project_root: Path,
    task: TestTask,
    payload_substr: str,
) -> tuple[bool, str, Path | None, Path | None]:
    """
    Returns (ok, message, target_path, backup_path).
    On ok, backup_path is written; caller must restore after run.
    """
    bp = task.bridge_point
    rel = str(bp.get("file") or "").replace("/", os.sep)
    line_no = int(bp.get("line") or 0)
    if not rel or line_no < 1:
        return False, "missing bridge file/line", None, None
    target = project_root.resolve() / rel
    if not target.is_file():
        return False, f"bridge file not found: {target}", None, None
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    idx = line_no - 1
    if idx < 0 or idx >= len(lines):
        return False, "bridge line out of range", None, None

    kind = _detect_bridge_kind(lines[idx])
    bridge_arg = str(task.carrier.get("name") or bp.get("argument") or "")
    bridge_file = str(bp.get("file") or rel).replace("\\", "/")
    new_lines: list[str] | None = None
    ok = False
    if kind == "setURI":
        new_lines, ok = _inject_seturi_block(lines, idx, task.path_id, bridge_file, line_no, bridge_arg, payload_substr)
    elif kind == "execute":
        new_lines, ok = _inject_execute_before(lines, idx, task.path_id, bridge_file, line_no, bridge_arg, payload_substr)
    elif kind == "httpget_ctor":
        new_lines, ok = _inject_httpget_after(lines, idx, task.path_id, bridge_file, line_no, bridge_arg, payload_substr)
    elif kind == "httppost_ctor":
        new_lines, ok = _inject_httppost_after(lines, idx, task.path_id, bridge_file, line_no, bridge_arg, payload_substr)
    else:
        return False, f"unsupported_bridge_kind:{kind}", target, None

    if not ok or new_lines is None:
        return False, "instrumentation_pattern_mismatch", target, None

    backup = target.with_suffix(target.suffix + ".pov_backup")
    shutil.copy2(target, backup)
    target.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return True, kind, target, backup


def restore_bridge_file(target: Path | None, backup: Path | None) -> None:
    if target is None:
        return
    try:
        if backup and backup.is_file():
            shutil.copy2(backup, target)
            backup.unlink(missing_ok=True)  # type: ignore[arg-type]
        elif backup:
            backup.unlink(missing_ok=True)  # type: ignore[arg-type]
    except OSError:
        pass


def resolve_mvn_executable() -> str:
    for cand in ("mvn.cmd", "mvn.exe", "mvn"):
        p = shutil.which(cand)
        if p:
            return p
    return "mvn"


def build_maven_compile_args(metadata_mvn_tokens: list[str] | None) -> list[str]:
    tokens = list(metadata_mvn_tokens or [])
    return [resolve_mvn_executable(), "-q", *tokens, "test-compile"]


def build_maven_test_args(metadata_mvn_tokens: list[str] | None) -> list[str]:
    tokens: list[str] = []
    for t in metadata_mvn_tokens or []:
        if t.startswith("-DskipTests") and "false" not in t.lower():
            continue
        tokens.append(t)
    if not any(x.startswith("-Dmaven.wagon") for x in tokens):
        tokens.extend(["-Dmaven.wagon.http.ssl.insecure=true", "-Dmaven.wagon.http.ssl.allowall=true"])
    return [resolve_mvn_executable(), "-q", *tokens, "-DskipTests=false", "-Dtest=auto.gen.pov.ThirdPhasePOVTest", "test"]


def _run_cmd(cwd: Path, args: list[str], log_file: Path | None) -> tuple[int, str, str]:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        shell=False,
    )
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text(out, encoding="utf-8")
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def compile_only(project_root: Path, maven_compile_args: list[str], log_path: Path | None = None) -> tuple[bool, str, str]:
    code, so, se = _run_cmd(project_root.resolve(), maven_compile_args, log_path)
    blob = (so + "\n" + se)[-12000:]
    return code == 0, so, blob


def _parse_markers(text: str) -> dict[str, Any]:
    markers: dict[str, Any] = {}
    if m := re.search(r"\[AUTO-POV\]\s*HIT_BRIDGE_POINT\s*path_id=\s*(\S+)", text):
        markers["hit_path_id"] = m.group(1).strip()
    if m := re.search(r"\[AUTO-POV\]\s*BRIDGE_FILE=\s*(\S+)", text):
        markers["bridge_file"] = m.group(1).strip()
    if m := re.search(r"\[AUTO-POV\]\s*PAYLOAD_OBSERVED=(true|false)", text, re.I):
        markers["payload_observed_raw"] = m.group(1).lower() == "true"
    if m := re.search(r"\[AUTO-POV\]\s*EXTRACT_HOST=(\S+)", text):
        markers["extract_host"] = m.group(1).strip()
    return markers


def _oracle_vuln_behavior(markers: dict[str, Any], expected_host: str) -> bool:
    host = str(markers.get("extract_host") or "")
    return bool(host) and host == expected_host


def compile_and_run(
    project_root: Path,
    task: TestTask,
    method_body: str,
    maven_compile_args: list[str],
    maven_test_args: list[str],
    work_dir: Path,
    *,
    skip_instrumentation: bool = False,
) -> RunSummary:
    root = project_root.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    gen_path = write_generated_test(root, method_body)
    (work_dir / "generated_test.java").write_text(gen_path.read_text(encoding="utf-8"), encoding="utf-8")

    inst_target: Path | None = None
    inst_backup: Path | None = None
    inst_meta = "skipped"
    payload_sub = "user@apache.org"
    if task.payload and "user@" in task.payload:
        payload_sub = task.payload.split("@")[0] + "@" if "@" in task.payload else "user@apache.org"

    if not skip_instrumentation:
        ok_inst, msg, inst_target, inst_backup = instrument_bridge_file(root, task, payload_sub)
        inst_meta = msg if ok_inst else f"instrumentation_failed:{msg}"
        if not ok_inst:
            return RunSummary(
                compile_success=False,
                run_success=False,
                bridge_hit=False,
                payload_observed_at_bridge=False,
                vulnerability_behavior_observed=False,
                vuln_api_invoked=False,
                runtime_logs="",
                compile_excerpt="",
                run_excerpt="",
                markers={"instrumentation": inst_meta},
                generated_test_path=str(gen_path.relative_to(root)),
                failure_stage="instrumentation_failed",
                metadata={"instrumentation_message": msg},
            )

    compile_log = work_dir / "compile.log"
    test_ok, so_c, se_c = compile_only(root, maven_compile_args, compile_log)
    compile_blob = (se_c + so_c)[-8000:]
    if not test_ok:
        restore_bridge_file(inst_target, inst_backup)
        return RunSummary(
            compile_success=False,
            run_success=False,
            bridge_hit=False,
            payload_observed_at_bridge=False,
            vulnerability_behavior_observed=False,
            vuln_api_invoked=False,
            runtime_logs="",
            compile_excerpt=compile_blob,
            run_excerpt="",
            markers={"instrumentation": inst_meta},
            generated_test_path=str(gen_path.relative_to(root)),
            failure_stage="COMPILE_FAILED",
            metadata={},
        )

    run_log = work_dir / "run.log"
    code, so_r, se_r = _run_cmd(root, maven_test_args, run_log)
    run_blob = (so_r + se_r)[-12000:]
    markers = _parse_markers(so_r + "\n" + se_r)
    bridge_hit = "[AUTO-POV] HIT_BRIDGE_POINT" in (so_r + se_r)
    payload_hit = bool(markers.get("payload_observed_raw"))
    expected_vuln_host = str(task.oracle.get("expected_vulnerable_host") or "apache.org")
    vuln_beh = _oracle_vuln_behavior(markers, expected_vuln_host)
    vuln_api = "[AUTO-POV] EXTRACT_HOST=" in (so_r + se_r)

    restore_bridge_file(inst_target, inst_backup)

    run_ok = code == 0
    failure_stage = ""
    if not run_ok:
        failure_stage = "RUN_FAILED"
    elif not bridge_hit:
        failure_stage = "CHAIN_NOT_HIT"
    elif not payload_hit:
        failure_stage = "PAYLOAD_NOT_OBSERVED"
    elif not vuln_beh:
        failure_stage = "VULN_BEHAVIOR_NOT_OBSERVED"
    else:
        failure_stage = "ALL_GATES_OK"

    return RunSummary(
        compile_success=True,
        run_success=run_ok,
        bridge_hit=bridge_hit,
        payload_observed_at_bridge=payload_hit,
        vulnerability_behavior_observed=vuln_beh,
        vuln_api_invoked=vuln_api,
        runtime_logs=(so_r + "\n" + se_r)[-20000:],
        compile_excerpt=compile_blob[-4000:],
        run_excerpt=run_blob,
        markers=markers,
        generated_test_path=str(gen_path.relative_to(root)),
        failure_stage=failure_stage,
        metadata={"instrumentation": inst_meta},
    )


def smoke_method_body(task: TestTask) -> str:
    payload = _java_escape(task.payload)
    return f"""
        java.net.URI malformed = new java.net.URI("{payload}");
        org.apache.http.HttpHost host = org.apache.http.client.utils.URIUtils.extractHost(malformed);
        System.out.println("[AUTO-POV] EXTRACT_HOST=" + host.getHostName());
""".strip()


def deterministic_no_llm_body(task: TestTask) -> str:
    return smoke_method_body(task) + "\n        org.junit.Assert.assertNotNull(host);\n"


def reference_snowflake_gcs_cve202013956_pov_method_body(task: TestTask) -> str:
    """
    与下游工程中已存在的 SnowflakeGCSClientCve202013956PathTest 等价的核心路径：
    presignedUrl → HttpGet → RestRequest.execute → setURI 桥接，配合插桩输出 AUTO-POV。
    仅适用于 SnowflakeGCSClient.download + RestRequest 该 CVE 路径实验。
    """
    p = _java_escape(task.payload)
    return f"""
        String malformedPresigned = "{p}";
        net.snowflake.client.core.HttpClientSettingsKey httpKey =
            new net.snowflake.client.core.HttpClientSettingsKey(net.snowflake.client.core.OCSPMode.FAIL_OPEN);
        net.snowflake.client.core.SFSession session =
            org.mockito.Mockito.mock(net.snowflake.client.core.SFSession.class);
        org.mockito.Mockito.when(session.getHttpClientKey()).thenReturn(httpKey);
        org.mockito.Mockito.when(session.getNetworkTimeoutInMilli()).thenReturn(60_000);

        java.util.Map<String, String> creds = new java.util.HashMap<String, String>();
        net.snowflake.client.jdbc.cloud.storage.StageInfo stage =
            net.snowflake.client.jdbc.cloud.storage.StageInfo.createStageInfo(
                "GCS", "unit-test-bucket", creds, "", null, null, false);
        net.snowflake.client.jdbc.cloud.storage.SnowflakeGCSClient gcsClient =
            net.snowflake.client.jdbc.cloud.storage.SnowflakeGCSClient.createSnowflakeGCSClient(
                stage, null, session);

        final java.util.concurrent.atomic.AtomicReference<java.net.URI> uriFromExecute =
            new java.util.concurrent.atomic.AtomicReference<java.net.URI>();

        org.apache.http.client.methods.CloseableHttpResponse okResponse =
            org.mockito.Mockito.mock(org.apache.http.client.methods.CloseableHttpResponse.class);
        org.apache.http.StatusLine statusLine = org.mockito.Mockito.mock(org.apache.http.StatusLine.class);
        org.mockito.Mockito.when(statusLine.getStatusCode()).thenReturn(200);
        org.mockito.Mockito.when(okResponse.getStatusLine()).thenReturn(statusLine);
        org.mockito.Mockito.when(okResponse.getEntity())
            .thenReturn(
                new org.apache.http.entity.ByteArrayEntity(
                    "ok".getBytes(java.nio.charset.StandardCharsets.UTF_8)));

        org.apache.http.impl.client.CloseableHttpClient httpClient =
            org.mockito.Mockito.mock(org.apache.http.impl.client.CloseableHttpClient.class);
        org.mockito.Mockito.when(
                httpClient.execute(
                    org.mockito.ArgumentMatchers.any(org.apache.http.client.methods.HttpUriRequest.class)))
            .thenAnswer(
                inv -> {{
                    org.apache.http.client.methods.HttpUriRequest req =
                        (org.apache.http.client.methods.HttpUriRequest) inv.getArguments()[0];
                    uriFromExecute.set(req.getURI());
                    return okResponse;
                }});

        java.nio.file.Path tmp = java.nio.file.Files.createTempDirectory("gcs-cve-thirdphase");
        String localDir = tmp.toAbsolutePath().toString();
        String destName = "blob.bin";

        try (org.mockito.MockedStatic<net.snowflake.client.core.HttpUtil> httpUtil =
                org.mockito.Mockito.mockStatic(net.snowflake.client.core.HttpUtil.class)) {{
            httpUtil
                .when(
                    () ->
                        net.snowflake.client.core.HttpUtil.getHttpClientWithoutDecompression(
                            org.mockito.ArgumentMatchers.any(
                                net.snowflake.client.core.HttpClientSettingsKey.class)))
                .thenReturn(httpClient);

            gcsClient.download(
                session,
                "GET unit-test",
                localDir,
                destName,
                1,
                "remote-loc",
                "stage-path",
                "region",
                malformedPresigned);

            httpUtil.verify(
                () ->
                    net.snowflake.client.core.HttpUtil.getHttpClientWithoutDecompression(
                        org.mockito.ArgumentMatchers.any(
                            net.snowflake.client.core.HttpClientSettingsKey.class)));
        }}

        java.net.URI afterFlow = uriFromExecute.get();
        org.junit.Assert.assertNotNull(afterFlow);
        org.apache.http.HttpHost extracted =
            org.apache.http.client.utils.URIUtils.extractHost(afterFlow);
        org.junit.Assert.assertNotNull(extracted);
        org.junit.Assert.assertEquals("apache.org", extracted.getHostName());
        System.out.println("[AUTO-POV] EXTRACT_HOST=" + extracted.getHostName());
""".strip()


def compile_only_test(project_root: Path, maven_compile_args: list[str], work_dir: Path) -> tuple[bool, str]:
    work_dir.mkdir(parents=True, exist_ok=True)
    p = work_dir / "compile_only.log"
    ok, _, blob = compile_only(project_root, maven_compile_args, p)
    return ok, blob
