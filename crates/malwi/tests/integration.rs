use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;
use tokio::time::timeout;

const INTEGRATION_TEST_DEADLINE: Duration = Duration::from_secs(360);
const INTEGRATION_TEST_INSTRUCTION: &str = "This is a bounded integration scan. Use only the required tool calls, prioritize the supplied evidence, and call finish with every schema field as soon as the task is grounded.";
const MALICIOUS_OPENING: &str = "Malicious — deliberately harmful behavior is present.";
const EXPLOITABLE_OPENING: &str = "Exploitable — no deliberate harm was established, but the code creates a path an attacker or compromised third party can abuse.";
const BENIGN_OPENING: &str =
    "Benign — no malicious or exploitable behavior was established in the examined code.";

fn require_integration_model() {
    let has_provider = [
        "LITELLM_PROVIDER",
        "LITELLM_API_KEY",
        "MISTRAL_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ]
    .iter()
    .any(|name| env::var(name).is_ok_and(|value| !value.is_empty()));
    let has_model = [
        "MODEL",
        "LITELLM_MODEL",
        "MISTRAL_MODEL",
        "ANTHROPIC_MODEL",
        "OPENAI_MODEL",
    ]
    .iter()
    .any(|name| env::var(name).is_ok_and(|value| !value.is_empty()));

    assert!(
        has_provider && has_model,
        "integration tests require a configured model provider and model; set a provider API key (or LITELLM_PROVIDER) and MODEL or the provider-specific *_MODEL variable, normally through the repository .env"
    );
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

async fn scan_fixture(name: &str) -> Value {
    require_integration_model();
    let work_dir = env::temp_dir().join(format!("malwi-integration-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&work_dir);
    fs::create_dir_all(&work_dir).expect("integration test working directory is created");
    let report = work_dir.join("analysis.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_malwi"));
    child
        .arg("analyze")
        .arg(fixture(name))
        .args([
            "--concurrency",
            "1",
            "--max-turns",
            "16",
            "--max-time",
            "90s",
            "--instruction",
            INTEGRATION_TEST_INSTRUCTION,
        ])
        .arg("--output")
        .arg(&report)
        .current_dir(&work_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let output = timeout(INTEGRATION_TEST_DEADLINE, child.output())
        .await
        .unwrap_or_else(|_| {
            panic!("integration scan of {name} exceeded {INTEGRATION_TEST_DEADLINE:?}")
        })
        .unwrap_or_else(|error| panic!("integration scan of {name} did not start: {error}"));
    assert!(
        output.status.success(),
        "integration scan of {name} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let analysis: Value = serde_json::from_slice(
        &fs::read(&report).unwrap_or_else(|error| panic!("read {}: {error}", report.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", report.display()));
    let _ = fs::remove_dir_all(&work_dir);
    analysis
}

fn finding_of_type<'a>(analysis: &'a Value, kind: &str) -> Option<&'a Value> {
    analysis["findings"]
        .as_array()?
        .iter()
        .find(|finding| finding["type"] == kind)
}

fn assert_summary_starts_with(analysis: &Value, opening: &str) {
    let summary = analysis["summary"]
        .as_str()
        .unwrap_or_else(|| panic!("missing report summary: {analysis:#}"));
    assert!(summary.starts_with(opening), "{analysis:#}");
}

fn assert_benign(analysis: &Value) {
    assert_eq!(analysis["verdict"], "benign", "{analysis:#}");
    assert_summary_starts_with(analysis, BENIGN_OPENING);
    assert!(
        analysis["findings"]
            .as_array()
            .is_some_and(|findings| findings
                .iter()
                .all(|finding| finding["verdict"] == "benign")),
        "{analysis:#}"
    );
}

#[tokio::test]
async fn unreferenced_obfuscated_exfiltration_is_malicious() {
    let analysis = scan_fixture("obfuscation-malicious").await;
    let finding = finding_of_type(&analysis, "obfuscation")
        .unwrap_or_else(|| panic!("missing obfuscation finding: {analysis:#}"));
    assert_eq!(analysis["verdict"], "malicious", "{analysis:#}");
    assert_summary_starts_with(&analysis, MALICIOUS_OPENING);
    assert_eq!(finding["verdict"], "malicious", "{analysis:#}");
    assert!(finding["payload"].is_string(), "{analysis:#}");
    assert!(finding["transform"].is_string(), "{analysis:#}");
    assert!(finding["sink"].is_string(), "{analysis:#}");
    assert!(finding["trigger"].is_object(), "{analysis:#}");
}

#[tokio::test]
async fn encoded_asset_without_execution_is_benign() {
    assert_benign(&scan_fixture("obfuscation-benign").await);
}

#[tokio::test]
async fn install_hook_download_and_execution_is_side_loading() {
    let analysis = scan_fixture("side-loading-exploitable").await;
    let finding = finding_of_type(&analysis, "side-loading")
        .unwrap_or_else(|| panic!("missing side-loading finding: {analysis:#}"));
    assert_summary_starts_with(&analysis, EXPLOITABLE_OPENING);
    assert_eq!(finding["verdict"], "exploitable", "{analysis:#}");
    assert!(finding["source"].is_string(), "{analysis:#}");
    assert!(finding["trigger"].is_object(), "{analysis:#}");
}

#[tokio::test]
async fn shipped_install_helper_is_not_side_loading() {
    assert_benign(&scan_fixture("side-loading-benign").await);
}

#[tokio::test]
async fn default_on_startup_analytics_is_telemetry() {
    let analysis = scan_fixture("telemetry-exploitable").await;
    let finding = finding_of_type(&analysis, "telemetry")
        .unwrap_or_else(|| panic!("missing telemetry finding: {analysis:#}"));
    assert_eq!(analysis["verdict"], "exploitable", "{analysis:#}");
    assert_summary_starts_with(&analysis, EXPLOITABLE_OPENING);
    assert_eq!(finding["verdict"], "exploitable", "{analysis:#}");
    assert_eq!(finding["user_consent"], false, "{analysis:#}");
    assert!(finding["provider"].is_string(), "{analysis:#}");
    assert!(finding["destination"].is_string(), "{analysis:#}");
    assert!(
        finding["data"]
            .as_array()
            .is_some_and(|data| !data.is_empty()),
        "{analysis:#}"
    );
    assert!(finding["trigger"]["phase"].is_string(), "{analysis:#}");
    assert!(
        finding["trigger"]["location"]["path"].is_string(),
        "{analysis:#}"
    );
    assert!(
        finding["trigger"]["execution_condition"].is_string(),
        "{analysis:#}"
    );
    assert!(finding["trigger"]["cadence"].is_string(), "{analysis:#}");
}

#[tokio::test]
async fn documented_default_off_usage_sharing_is_benign() {
    assert_benign(&scan_fixture("telemetry-benign").await);
}
