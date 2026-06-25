from __future__ import annotations

from typing import Any

from src.third_phase.models import TestTask


def _join_sigs(task: TestTask) -> str:
    parts = [str(task.entry.get("signature") or "")]
    parts.extend(str(n.get("signature") or "") for n in (task.method_path or []) if isinstance(n, dict))
    return " ".join(parts)


def classify_path_profile(task: TestTask) -> str:
    blob = _join_sigs(task).lower()
    ent_file = str(task.entry.get("file") or "").lower()
    bp_file = str(task.bridge_point.get("file") or "").lower()
    if "snowflakegcsclient" in blob or "presignedurl" in blob or "gcsclient" in blob:
        return "gcs_presigned_url"
    if "sftrustmanager" in blob or "ocsp" in blob or "sftrustmanager" in ent_file or "sftrustmanager" in bp_file:
        return "sf_trust_ocsp"
    return "generic_http_execute"


def _vulnerable_dependency(case_meta: dict[str, Any], ds_meta: dict[str, Any]) -> dict[str, Any]:
    up = case_meta.get("upstream") or {}
    up_pkg = up.get("package") or {}
    dh = ds_meta.get("dependency_hint") or {}
    return {
        "group_id": str(dh.get("group_id") or up_pkg.get("group_id") or ""),
        "artifact_id": str(dh.get("artifact_id") or up_pkg.get("artifact_id") or ""),
        "vulnerable_version": str(dh.get("version") or up_pkg.get("affected_version") or ""),
        "fixed_version": str(up_pkg.get("fixed_version") or ""),
    }


def _reachability_explanation(status: str) -> str:
    s = (status or "").strip()
    if "confirmed" in s.lower():
        return (
            f"Static reachability label is `{s}`: stronger evidence that the parameter may propagate toward the bridge; "
            "the Phase-3 test still dynamically exercises the path."
        )
    if "candidate" in s.lower():
        return (
            f"Static reachability label is `{s}`: this is a candidate path, not a proof that runtime propagation is guaranteed. "
            "The goal of Phase-3 is to attempt a dynamic validation via a compilable JUnit body."
        )
    if s:
        return f"Static reachability label is `{s}`."
    return "Reachability status was not provided; treat the selected path as an experimentally prioritized candidate."


def _java_escape_literal(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _snowflake_gcs_verified_recipe(task: TestTask, expected_vuln_host: str) -> dict[str, Any]:
    """与本仓库 SnowflakeGCSClientCve202013956PathTest 一致的、已通过门禁的构造要点（供 LLM 严格模仿）。"""
    p = (
        task.payload.replace("\\", "\\\\")
        .replace("\r", "")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )
    host = _java_escape_literal(expected_vuln_host)
    skeleton = f"""String malformedPresigned = "{p}";
net.snowflake.client.core.HttpClientSettingsKey __httpKey =
    new net.snowflake.client.core.HttpClientSettingsKey(net.snowflake.client.core.OCSPMode.FAIL_OPEN);
net.snowflake.client.core.SFSession __session =
    org.mockito.Mockito.mock(net.snowflake.client.core.SFSession.class);
org.mockito.Mockito.when(__session.getHttpClientKey()).thenReturn(__httpKey);
org.mockito.Mockito.when(__session.getNetworkTimeoutInMilli()).thenReturn(60_000);
java.util.Map<String, String> __creds = new java.util.HashMap<String, String>();
net.snowflake.client.jdbc.cloud.storage.StageInfo __stage =
    net.snowflake.client.jdbc.cloud.storage.StageInfo.createStageInfo(
        "GCS", "unit-test-bucket", __creds, "", null, null, false);
net.snowflake.client.jdbc.cloud.storage.SnowflakeGCSClient __gcs =
    net.snowflake.client.jdbc.cloud.storage.SnowflakeGCSClient.createSnowflakeGCSClient(__stage, null, __session);
java.util.concurrent.atomic.AtomicReference<java.net.URI> __uriBox =
    new java.util.concurrent.atomic.AtomicReference<java.net.URI>();
org.apache.http.client.methods.CloseableHttpResponse __resp =
    org.mockito.Mockito.mock(org.apache.http.client.methods.CloseableHttpResponse.class);
org.apache.http.StatusLine __sl = org.mockito.Mockito.mock(org.apache.http.StatusLine.class);
org.mockito.Mockito.when(__sl.getStatusCode()).thenReturn(200);
org.mockito.Mockito.when(__resp.getStatusLine()).thenReturn(__sl);
org.mockito.Mockito.when(__resp.getEntity()).thenReturn(
    new org.apache.http.entity.ByteArrayEntity("ok".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
org.apache.http.impl.client.CloseableHttpClient __http =
    org.mockito.Mockito.mock(org.apache.http.impl.client.CloseableHttpClient.class);
org.mockito.Mockito.when(__http.execute(org.mockito.ArgumentMatchers.any(org.apache.http.client.methods.HttpUriRequest.class)))
    .thenAnswer(inv -> {{
      __uriBox.set(((org.apache.http.client.methods.HttpUriRequest) inv.getArguments()[0]).getURI());
      return __resp;
    }});
java.nio.file.Path __tmp = java.nio.file.Files.createTempDirectory("pov-gcs");
try (org.mockito.MockedStatic<net.snowflake.client.core.HttpUtil> __hu =
        org.mockito.Mockito.mockStatic(net.snowflake.client.core.HttpUtil.class)) {{
  __hu.when(() -> net.snowflake.client.core.HttpUtil.getHttpClientWithoutDecompression(
          org.mockito.ArgumentMatchers.any(net.snowflake.client.core.HttpClientSettingsKey.class))).thenReturn(__http);
  __gcs.download(__session, "GET unit-test", __tmp.toString(), "blob.bin", 1,
      "remote-loc", "stage-path", "region", malformedPresigned);
}}
org.apache.http.HttpHost __host =
    org.apache.http.client.utils.URIUtils.extractHost(__uriBox.get());
System.out.println("[AUTO-POV] EXTRACT_HOST=" + __host.getHostName());
org.junit.Assert.assertEquals("{host}", __host.getHostName());"""
    return {
        "reference_test_in_repo": "net.snowflake.client.jdbc.cloud.storage.SnowflakeGCSClientCve202013956PathTest",
        "priority": "If this path_profile is gcs_presigned_url for Snowflake JDBC, follow this recipe — it matches a passing verifier run.",
        "must_follow": [
            "Use SnowflakeGCSClient.createSnowflakeGCSClient(stage, null, session). Never use `new SnowflakeGCSClient()`.",
            "StageInfo.createStageInfo(\"GCS\", \"unit-test-bucket\", new java.util.HashMap<>(), \"\", null, null, false) (or equivalent creds map).",
            "Mock SFSession.getHttpClientKey() with a real net.snowflake.client.core.HttpClientSettingsKey built with OCSPMode.FAIL_OPEN (not java.lang.Object).",
            "mockStatic scope class MUST be net.snowflake.client.core.HttpUtil — NOT net.snowflake.client.jdbc.HttpUtil (common compile error).",
            "Stub HttpUtil.getHttpClientWithoutDecompression(ArgumentMatchers.any(HttpClientSettingsKey.class)) → mocked CloseableHttpClient; execute() captures HttpUriRequest.getURI().",
            "Pass the CVE payload string as the presignedUrl argument to download(...).",
            f"After download, URIUtils.extractHost(observedUri).getHostName() should equal `{expected_vuln_host}`; print [AUTO-POV] EXTRACT_HOST= that hostname.",
            "Do not print fake shortened bridge markers; instrumentation at RestRequest emits HIT_BRIDGE_POINT / PAYLOAD_OBSERVED when the real path runs.",
        ],
        "minimal_skeleton_all_fqn": skeleton,
    }


def build_upstream_poc_reference(task: TestTask, case_meta: dict[str, Any], ds_meta: dict[str, Any]) -> dict[str, Any]:
    apis = case_meta.get("vulnerable_apis") or ds_meta.get("vulnerable_apis") or []
    api0 = apis[0] if apis and isinstance(apis[0], dict) else {}
    sig = str(api0.get("signature") or "org.apache.http.client.utils.URIUtils.extractHost(java.net.URI): org.apache.http.HttpHost")
    poc = case_meta.get("poc") or {}
    expected = str(poc.get("expected_vulnerable_result") or task.oracle.get("expected_vulnerable_host") or "apache.org")
    return {
        "allowed": True,
        "purpose": "Use the upstream PoC to understand vulnerable behavior and the oracle; adapt it into a downstream unit test.",
        "vulnerable_api": sig,
        "poc_payload": task.payload,
        "poc_expected_result": expected,
        "minimal_oracle_snippet": (
            f'java.net.URI __pocUri = new java.net.URI("{task.payload}");\n'
            "org.apache.http.HttpHost __pocHost = org.apache.http.client.utils.URIUtils.extractHost(__pocUri);\n"
            'System.out.println("[AUTO-POV] EXTRACT_HOST=" + __pocHost.getHostName());\n'
        ),
        "how_to_adapt_to_downstream": (
            "Prefer constructing or observing a URI/HttpUriRequest through the selected downstream entry (or a direct callee) "
            "so the malformed authority reaches the instrumented bridge. "
            "You may additionally keep a compact URIUtils.extractHost oracle on the task payload as auxiliary evidence "
            "when downstream URI capture is difficult."
        ),
    }


def build_test_plan(
    task: TestTask,
    api_facts: dict[str, Any],
    *,
    case_meta: dict[str, Any],
    ds_meta: dict[str, Any],
    verifier_required_markers: list[str],
) -> dict[str, Any]:
    profile = classify_path_profile(task)
    entry_sig = str(task.entry.get("signature") or "")
    bridge_sig = str(task.bridge_point.get("signature") or "")
    path_nodes = [str(n.get("signature") or "") for n in (task.method_path or []) if isinstance(n, dict)][:25]
    expected_host = str(task.oracle.get("expected_vulnerable_host") or "apache.org")

    why = (
        f"Selected for rank={task.rank}, score={task.score:.4f}. "
        f"Entry `{entry_sig}` is paired with bridge `{bridge_sig}` in the static path bundle."
    )
    if task.selection_reason:
        why += " Selection notes: " + "; ".join(str(x) for x in task.selection_reason[:6])

    payload_block = {
        "value": task.payload,
        "purpose": (
            "Malformed-authority URI from upstream/CVE PoC; when parsed by a vulnerable HttpClient line, "
            "URIUtils.extractHost can prefer the wrong authority component."
        ),
        "expected_vulnerable_behavior": (
            f"URIUtils.extractHost(...) yields HttpHost authority `{expected_host}` on vulnerable httpclient versions."
        ),
        "expected_marker": f"[AUTO-POV] EXTRACT_HOST={expected_host}",
    }

    injection: dict[str, Any]
    entry_plan: dict[str, Any]
    mocking: dict[str, Any]
    bridge_obs: dict[str, Any]
    pitfalls: list[str]
    recommended_strategy_steps: list[str]

    if profile == "gcs_presigned_url":
        injection = {
            "preferred_source": "SnowflakeGCSClient.download presignedUrl parameter (or equivalent URL-bearing argument)",
            "preferred_argument_name": "presignedUrl",
            "preferred_argument_index": "infer from download(...) signature in source",
            "how_to_inject": (
                f"Pass the CVE payload string `{task.payload}` as the presignedUrl (or the URL argument that feeds RestRequest/HttpClient)."
            ),
            "fallback_sources": [
                "Any downstream factory/builder that ultimately sets URI on HttpUriRequest for this path",
                "HttpGet/HttpPost constructors if the selected path routes through them",
            ],
        }
        entry_plan = {
            "target_class": str(task.entry.get("declaring_type") or "net.snowflake.client.jdbc.cloud.storage.SnowflakeGCSClient"),
            "target_method": entry_sig,
            "constructor_strategy": (
                "Mandatory for Snowflake JDBC GCS path: "
                "SnowflakeGCSClient.createSnowflakeGCSClient(StageInfo stage, StageCredentialExtractor|null, SFSession session). "
                "Build StageInfo via StageInfo.createStageInfo(...). Do NOT call `new SnowflakeGCSClient()`."
            ),
            "minimal_required_arguments": [
                "Session/config object as required by download(...)",
                "String presignedUrl carrying the CVE payload",
            ],
            "notes": (
                "Mirror snowflake_gcs_verified_recipe / SnowflakeGCSClientCve202013956PathTest: HttpClientSettingsKey + OCSPMode.FAIL_OPEN "
                "on mocked SFSession.getHttpClientKey(); mockStatic net.snowflake.client.core.HttpUtil (not jdbc.HttpUtil)."
            ),
        }
        mocking = {
            "must_avoid_real_network": True,
            "recommended_mocks": [
                {
                    "target": "net.snowflake.client.core.HttpUtil.getHttpClientWithoutDecompression(HttpClientSettingsKey)",
                    "reason": "Must mockStatic the core.HttpUtil class — jdbc.HttpUtil does not exist and breaks compilation.",
                    "suggested_approach": (
                        "MockedStatic<net.snowflake.client.core.HttpUtil> + when(() -> HttpUtil.getHttpClientWithoutDecompression(any(HttpClientSettingsKey.class)))"
                    ),
                },
                {
                    "target": "CloseableHttpClient.execute(HttpUriRequest)",
                    "reason": "Capture URI and print AUTO-POV markers without contacting the internet",
                    "suggested_approach": "Answer with a fake CloseableHttpResponse + StatusLine; read request.getURI()",
                },
                {
                    "target": "SFSession / cloud storage context objects",
                    "reason": "Avoid needing live Snowflake credentials",
                    "suggested_approach": "Mockito @Mock / manual stub with minimal getters used by download",
                },
            ],
            "network_boundary": "Never open real TCP/TLS; intercept at HttpClient.execute or earlier URI construction.",
        }
        bridge_obs = {
            "bridge_call": bridge_sig,
            "what_to_observe": "HttpUriRequest.getURI(), URI string at bridge, or RestRequest.execute argument",
            "suggested_marker": "[AUTO-POV] PAYLOAD_OBSERVED=true (also emitted by instrumentation when payload substring hits bridge URI)",
            "notes": (
                "Printing extra diagnostics is encouraged for evidence; hard verifier gates remain compile/run/bridge/payload/vuln host."
            ),
        }
        pitfalls = [
            "Avoid relying only on URIUtils.extractHost on a standalone URI without attempting the downstream entry when possible.",
            "Do not add imports; use fully qualified names for classes not in the ThirdPhasePOVTest template imports.",
            "Do not perform real HTTP requests.",
            "Never use `new SnowflakeGCSClient()` — use SnowflakeGCSClient.createSnowflakeGCSClient(...).",
            "Never mockStatic net.snowflake.client.jdbc.HttpUtil — the correct class is net.snowflake.client.core.HttpUtil.",
            "Never return Mockito.mock(Object.class) from SFSession.getHttpClientKey(); return HttpClientSettingsKey instead.",
            "Do not manually print a fake `[AUTO-POV] HIT_BRIDGE_POINT` line without path_id; rely on RestRequest instrumentation.",
        ]
        recommended_strategy_steps = [
            "Follow snowflake_gcs_verified_recipe.minimal_skeleton_all_fqn variable-by-variable (rename vars if needed).",
            "Create HttpClientSettingsKey + mocked SFSession returning that key.",
            "StageInfo.createStageInfo + SnowflakeGCSClient.createSnowflakeGCSClient(stage, null, session).",
            "mockStatic(core.HttpUtil) and stub getHttpClientWithoutDecompression → fake CloseableHttpClient capturing URI in execute().",
            "Call download(..., malformedPresigned) with the exact CVE payload.",
            f"URIUtils.extractHost(capturedUri) and print [AUTO-POV] EXTRACT_HOST={expected_host} (JUnit assertEquals optional).",
        ]
    elif profile == "sf_trust_ocsp":
        injection = {
            "preferred_source": "OCSP responder URL / JVM system property / config field feeding URL construction (if visible in snippets)",
            "preferred_argument_name": "unknown_without_snippet_evidence",
            "preferred_argument_index": None,
            "how_to_inject": (
                "Prefer a configuration-controlled URL or static field initializer discovered in snippets; "
                "do not assume checkServerTrusted parameters carry the CVE payload."
            ),
            "fallback_sources": ["system properties", "static configuration blocks", "test-only overrides"],
            "source_uncertain": True,
        }
        entry_plan = {
            "target_class": str(task.entry.get("declaring_type") or ""),
            "target_method": entry_sig,
            "constructor_strategy": "Prefer smallest construction graph from existing tests; otherwise Mockito collaborators.",
            "minimal_required_arguments": [],
            "notes": (
                "SFTrustManager / OCSP paths often lack a clean presignedUrl-style sink; treat as secondary to GCS presignedUrl paths."
            ),
        }
        mocking = {
            "must_avoid_real_network": True,
            "recommended_mocks": [
                {
                    "target": "External OCSP / HTTP fetch collaborators",
                    "reason": "Avoid live revocation fetch",
                    "suggested_approach": "Stub URL connection or inject a fixed OCSP URL string under test control",
                }
            ],
            "network_boundary": "Block outbound calls before HttpClient.execute or URL.openConnection.",
        }
        bridge_obs = {
            "bridge_call": bridge_sig,
            "what_to_observe": "URI or HttpUriRequest reaching vulnerable HttpClient bridge",
            "suggested_marker": "[AUTO-POV] PAYLOAD_OBSERVED=true",
            "notes": "If payload propagation is unclear, upstream PoC oracle may be used as auxiliary evidence per upstream_poc_reference.",
        }
        pitfalls = [
            "Do not default to assuming payload enters via certificate arrays in checkServerTrusted without snippet proof.",
            "Prefer configuration or static-field override when source_uncertain is true.",
        ]
        recommended_strategy_steps = [
            "Inspect snippets for URL sources (properties, constants, config).",
            "Attempt to route CVE payload into that source while still calling the selected downstream entry when feasible.",
            "Use mocks to avoid real network.",
            "Include upstream oracle as auxiliary evidence if needed.",
        ]
    else:
        injection = {
            "preferred_source": str(task.carrier.get("name") or "parameter inferred from carrier / parameter_flow"),
            "preferred_argument_name": str(task.carrier.get("name") or ""),
            "preferred_argument_index": None,
            "how_to_inject": (
                "Pass the CVE payload into the argument or builder that feeds the HttpUriRequest/URI at the bridge, "
                "following parameter_flow nodes when available."
            ),
            "fallback_sources": ["HttpGet/HttpPost URI constructor", "URIBuilder", "RestRequest.execute argument"],
        }
        entry_plan = {
            "target_class": str(task.entry.get("declaring_type") or ""),
            "target_method": entry_sig,
            "constructor_strategy": "Use api_facts + snippets; prefer patterns copied from existing_test_usage.",
            "minimal_required_arguments": [],
            "notes": "Drive the selected entry toward the bridge kind shown in bridge_point (setURI, HttpGet ctor, execute, ...).",
        }
        mocking = {
            "must_avoid_real_network": True,
            "recommended_mocks": [
                {
                    "target": "CloseableHttpClient / connection factory",
                    "reason": "Capture execute and avoid outbound calls",
                    "suggested_approach": "Mockito mock / fake client",
                }
            ],
            "network_boundary": "Intercept HttpClient.execute or earlier.",
        }
        bridge_obs = {
            "bridge_call": bridge_sig,
            "what_to_observe": "URI at bridge, HttpUriRequest, or equivalent",
            "suggested_marker": "[AUTO-POV] PAYLOAD_OBSERVED=true",
            "notes": "Stronger: if you capture request.getURI(), you may also run URIUtils.extractHost on it — optional, not mandatory.",
        }
        pitfalls = [
            "Avoid relying only on a standalone upstream PoC if you can call the downstream entry first.",
            "Do not assume imports exist beyond the template; use fully qualified names.",
        ]
        recommended_strategy_steps = [
            "Build minimal objects to call the entry.",
            "Inject payload per parameter_flow / carrier hints.",
            "Mock Http client to capture URI and satisfy markers.",
            "Optionally add upstream oracle snippet for EXTRACT_HOST.",
        ]

    junit = (api_facts.get("test_framework") or {}).get("junit") or "unknown"
    mockito = bool((api_facts.get("test_framework") or {}).get("mockito_available"))

    code_gen = {
        "output_format": "method_body_only",
        "no_package": True,
        "no_imports": True,
        "no_class_wrapper": True,
        "no_test_annotation": True,
        "use_fully_qualified_names_for_unimported_classes": True,
        "avoid_real_network": True,
        "prefer_junit4_or_existing_project_test_style": f"Detected JUnit flavor: {junit}; Mockito available in POM: {mockito}.",
        "template_imports": api_facts.get("template_imports", []),
    }

    assertion_plan = {
        "required_runtime_markers": list(verifier_required_markers),
        "recommended_assertions": [
            f"Prefer logs containing EXTRACT_HOST authority `{expected_host}` matching the vulnerable parsing outcome.",
            "Ensure instrumentation-visible lines include HIT_BRIDGE_POINT and PAYLOAD_OBSERVED when bridge executes.",
        ],
        "success_principle": (
            "Verifier hard gates (unchanged): compile_success, run_success, bridge_hit, payload_observed_at_bridge, "
            "vulnerability_behavior_observed — satisfy them while maximizing downstream path realism."
        ),
    }

    result: dict[str, Any] = {
        "goal": (
            "Generate a JUnit test method body that drives the selected downstream entry with the CVE payload and "
            "produces verifier-visible AUTO-POV evidence."
        ),
        "cve_id": task.cve_id,
        "path_profile": profile,
        "vulnerable_dependency": _vulnerable_dependency(case_meta, ds_meta),
        "payload": payload_block,
        "selected_path_summary": {
            "entry_method": entry_sig,
            "bridge_method": bridge_sig,
            "path_nodes": path_nodes,
            "reachability_status": task.reachability_status or "unknown",
            "why_selected": why,
            "reachability_interpretation": _reachability_explanation(task.reachability_status),
        },
        "payload_injection_plan": injection,
        "entry_invocation_plan": entry_plan,
        "mocking_plan": mocking,
        "bridge_observation_plan": bridge_obs,
        "upstream_poc_reference": build_upstream_poc_reference(task, case_meta, ds_meta),
        "assertion_plan": assertion_plan,
        "code_generation_constraints": code_gen,
        "known_pitfalls": pitfalls
        + [
            "Missing throws on checked exceptions breaks compilation inside the template method.",
            "Returning null CloseableHttpResponse often causes NPE — return minimal stub objects.",
            "Avoid Mockito APIs requiring mockito-inline unless the POM proves it is available.",
        ],
        "recommended_strategy_steps": recommended_strategy_steps,
    }
    if profile == "gcs_presigned_url":
        result["snowflake_gcs_verified_recipe"] = _snowflake_gcs_verified_recipe(task, expected_host)
    return result
