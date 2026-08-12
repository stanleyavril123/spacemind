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

#[test]
fn applies_ignore_and_protect_rules_end_to_end() {
    let directory = TestDirectory::new();
    let ignored = directory.0.join("ignored");
    let protected = directory.0.join("Documents");
    fs::create_dir(&ignored).unwrap();
    fs::create_dir(&protected).unwrap();
    fs::write(ignored.join("not-scanned.bin"), [9_u8; 9]).unwrap();
    fs::write(protected.join("kept.bin"), [7_u8; 16]).unwrap();
    fs::write(directory.0.join("copy.bin"), [7_u8; 16]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_spacemind"))
        .args([
            "scan",
            directory.0.to_str().unwrap(),
            "--format",
            "json",
            "--duplicate-min-size",
            "1B",
            "--large-threshold",
            "1B",
            "--ignore",
            ignored.to_str().unwrap(),
            "--protect",
            protected.to_str().unwrap(),
            "--no-default-protections",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["scan"]["total_size_bytes"], 32);
    assert_eq!(json["scan"]["ignored_paths"].as_array().unwrap().len(), 1);
    assert_eq!(json["policy"]["protected_items"], 2);
    assert!(json["policy"]["suppressed_recommendations"].as_u64().unwrap() >= 2);
    assert!(json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| !finding["path"].as_str().unwrap().starts_with(protected.to_str().unwrap())));
    let group = &json["duplicates"]["groups"][0];
    assert_eq!(group["protected_file_count"], 1);
    assert_eq!(
        group["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["protected"] == true)
            .count(),
        1
    );
}

#[test]
fn emits_specific_deterministic_categories_in_json() {
    let directory = TestDirectory::new();
    let project = directory.0.join("project");
    let target = project.join("target");
    let dependencies = project.join("node_modules");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir(&dependencies).unwrap();
    fs::write(project.join("Cargo.toml"), b"[package]\nname = \"example\"").unwrap();
    fs::write(target.join("artifact.bin"), [1_u8; 17]).unwrap();
    fs::write(dependencies.join("package.js"), [2_u8; 19]).unwrap();
    fs::write(directory.0.join("machine.qcow2"), [3_u8; 23]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_spacemind"))
        .args([
            "scan",
            directory.0.to_str().unwrap(),
            "--format",
            "json",
            "--large-threshold",
            "1GiB",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    let categories = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|finding| finding["category"].as_str())
        .collect::<Vec<_>>();

    assert!(categories.contains(&"rust_build_artifacts"));
    assert!(categories.contains(&"node_modules"));
    assert!(categories.contains(&"virtual_machine"));

    let relationship_kinds = json["relationships"]["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|relationship| relationship["kind"].as_str())
        .collect::<Vec<_>>();
    assert!(relationship_kinds.contains(&"build_directory_project"));

    let rust_finding = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["category"] == "rust_build_artifacts")
        .unwrap();
    assert!(rust_finding["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|evidence| evidence
            .as_str()
            .is_some_and(|value| value.starts_with("Source project:"))));
}

#[test]
fn zero_argument_launch_scans_the_current_directory_without_a_terminal() {
    let directory = TestDirectory::new();
    fs::write(directory.0.join("example.bin"), [7_u8; 16]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_spacemind"))
        .current_dir(&directory.0)
        .output()
        .unwrap();

    assert!(output.status.success());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("SPACEMIND"));
    assert!(report.contains("worth reviewing"));
    assert!(report.contains("Nothing was deleted or modified"));
}
