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
fn scans_a_directory_and_emits_json() {
    let directory = TestDirectory::new();
    fs::write(directory.0.join("example.bin"), [0_u8; 16]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_spacemind"))
        .args(["scan", directory.0.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"total_size_bytes\": 16"));
    assert!(stdout.contains("example.bin"));
}
