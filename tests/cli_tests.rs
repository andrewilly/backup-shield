use assert_cmd::Command;
use predicates::prelude::*;

fn backup_shield() -> Command {
    Command::cargo_bin("backup-shield").unwrap()
}

#[test]
fn test_help_flag() {
    backup_shield()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("backup-shield"));
}

#[test]
fn test_init_valid_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("repo");

    backup_shield()
        .arg("init")
        .arg(path.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("initialized"));
}

#[test]
fn test_init_invalid_path_fails() {
    backup_shield()
        .arg("init")
        .arg("/nonexistent/parent/for/init/test")
        .assert()
        .failure();
}

#[test]
fn test_init_help() {
    backup_shield()
        .arg("init")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialize"));
}

#[test]
fn test_backup_no_repo() {
    backup_shield()
        .arg("backup")
        .arg(".")
        .arg("--repo")
        .arg("/nonexistent/repo/for/backup/test")
        .assert()
        .failure();
}

#[test]
fn test_backup_help() {
    backup_shield()
        .arg("backup")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("source"));
}

#[test]
fn test_restore_help() {
    backup_shield()
        .arg("restore")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dry-run"));
}

#[test]
fn test_restore_dry_run_flag_in_help() {
    backup_shield()
        .arg("restore")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn test_snapshots_help() {
    backup_shield()
        .arg("snapshots")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("List snapshots"));
}

#[test]
fn test_snapshots_no_repo() {
    backup_shield()
        .arg("snapshots")
        .arg("--repo")
        .arg("/nonexistent/repo/for/snapshots/test")
        .assert()
        .success()
        .stdout(predicate::str::contains("No snapshots"));
}

#[test]
fn test_verify_help() {
    backup_shield()
        .arg("verify")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Verify"));
}

#[test]
fn test_prune_help() {
    backup_shield()
        .arg("prune")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Remove"));
}

#[test]
fn test_compact_help() {
    backup_shield()
        .arg("compact")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Compact"));
}

#[test]
fn test_stats_help() {
    backup_shield()
        .arg("stats")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("repository"));
}
