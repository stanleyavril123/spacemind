use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "spacemind-cli-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn scans_a_directory_and_emits_duplicate_json() {
    let directory = TestDirectory::new();
    fs::write(directory.0.join("example.bin"), [7_u8; 16]).unwrap();
    fs::write(directory.0.join("example-copy.bin"), [7_u8; 16]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_spacemind"))
        .args([
            "scan",
            directory.0.to_str().unwrap(),
            "--format",
            "json",
            "--duplicate-min-size",
            "1B",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["scan"]["total_size_bytes"], 32);
    assert_eq!(json["duplicates"]["groups"].as_array().unwrap().len(), 1);
    assert_eq!(
        json["duplicates"]["groups"][0]["unique_file_count"],
        2
    );
    assert!(json["duplicates"]["potential_recovery_allocated_bytes"]
        .as_u64()
        .unwrap()
        > 0);
}
