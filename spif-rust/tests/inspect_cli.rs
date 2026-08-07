use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_spif-viewer")
}

#[test]
fn inspect_json_reports_signed_and_verified() {
    let out = Command::new(bin())
        .args(["inspect", "--json", "sample.spif"])
        .output()
        .expect("run spif-viewer inspect");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["_signed"], serde_json::json!(true));
    assert_eq!(v["_verified"], serde_json::json!(true));
}

#[test]
fn inspect_pretty_is_indented_json() {
    let out = Command::new(bin())
        .args(["inspect", "--pretty", "sample.spif"])
        .output()
        .expect("run spif-viewer inspect");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\n  \""));
    let _: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
}

#[test]
fn inspect_missing_file_exits_nonzero() {
    let out = Command::new(bin())
        .args(["inspect", "--json", "does_not_exist.spif"])
        .output()
        .expect("run spif-viewer inspect");
    assert!(!out.status.success());
}
