//! 契约对拍（K6）：消费 TS 侧生成的 test/fixtures/rpc/protocol-golden.json。
//! TS 生成、Rust 只消费——本测试不生成夹具，只验证「Rust 解析器能读懂
//! 单一事实源产出的每一帧」与关键样本的结构。

use serde_json::Value;

const GOLDEN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test/fixtures/rpc/protocol-golden.json"
);

#[derive(serde::Deserialize)]
struct GoldenSample {
    name: String,
    wire: String,
}

#[derive(serde::Deserialize)]
struct GoldenFixture {
    #[serde(rename = "protocolVersion")]
    protocol_version: String,
    samples: Vec<GoldenSample>,
}

fn load_fixture() -> GoldenFixture {
    let raw = std::fs::read_to_string(GOLDEN_PATH)
        .unwrap_or_else(|e| panic!("golden fixture unreadable ({GOLDEN_PATH}): {e}"));
    serde_json::from_str(&raw).expect("golden fixture is valid JSON")
}

/// 与 TS 侧 FrameReader 同语义：`\n` 分帧、4MB 上限、JSON 解析。
fn parse_wire(wire: &str) -> Result<Value, String> {
    let line = wire.strip_suffix('\n').ok_or("frame must end with \\n")?;
    if line.len() > 4 * 1024 * 1024 {
        return Err("frame exceeds 4MB limit".to_string());
    }
    serde_json::from_str(line).map_err(|e| format!("invalid JSON frame: {e}"))
}

#[test]
fn golden_fixture_exists_and_is_valid() {
    let fixture = load_fixture();
    assert_eq!(fixture.protocol_version, "0.2.0");
    assert!(fixture.samples.len() >= 6, "expected the full sample set");
}

#[test]
fn every_sample_wire_is_one_parseable_frame() {
    let fixture = load_fixture();
    for sample in &fixture.samples {
        assert!(sample.wire.ends_with('\n'), "{}: wire must end with \\n", sample.name);
        let parsed = parse_wire(&sample.wire)
            .unwrap_or_else(|e| panic!("{}: {})", sample.name, e));
        assert!(parsed.is_object(), "{}: frame must be a JSON object", sample.name);
        assert_eq!(
            parsed.get("jsonrpc").and_then(|v| v.as_str()),
            Some("2.0"),
            "{}: jsonrpc 2.0 envelope required",
            sample.name
        );
    }
}

#[test]
fn hello_result_sample_echoes_protocol_version_and_fingerprint() {
    let fixture = load_fixture();
    let hello = fixture
        .samples
        .iter()
        .find(|s| s.name == "hello.result")
        .expect("hello.result sample required");
    let value: Value = serde_json::from_str(hello.wire.trim_end_matches('\n')).unwrap();
    let result = value.get("result").expect("hello.result must carry result");
    assert_eq!(
        result.get("protocolVersion").and_then(|v| v.as_str()),
        Some("0.2.0")
    );
    let fingerprint = result
        .get("certFingerprint")
        .and_then(|v| v.as_str())
        .expect("certFingerprint required");
    assert_eq!(fingerprint.len(), 64, "sha256 hex fingerprint is 64 chars");
}

#[test]
fn error_sample_carries_the_forbidden_code() {
    let fixture = load_fixture();
    let error_sample = fixture
        .samples
        .iter()
        .find(|s| s.name == "error.forbidden")
        .expect("error.forbidden sample required");
    let value: Value = serde_json::from_str(error_sample.wire.trim_end_matches('\n')).unwrap();
    let error = value.get("error").expect("error sample must carry error");
    assert_eq!(error.get("code").and_then(|v| v.as_i64()), Some(-32002));
}
