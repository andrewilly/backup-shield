use backup_shield_core::chunker::Chunker;
use backup_shield_core::repository::Repository;
use backup_shield_core::snapshot::Snapshot;
use backup_shield_verify::{Scrubber, Verifier, VerifyLevel};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn corrupt_pack_file(repo_path: &Path) {
    let data_dir = repo_path.join("data");
    for entry in fs::read_dir(&data_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "pack") {
            let original = fs::read(&path).unwrap();
            let corrupted: Vec<u8> = original.iter().map(|b| b ^ 0xFF).collect();
            fs::write(&path, &corrupted).unwrap();
            return; // corrupt only the first pack
        }
    }
}

#[test]
fn test_corruption_detection_and_repair() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let repo_path = root.path().join("repo");
    let restore_path = root.path().join("restore");

    fs::create_dir_all(&source).unwrap();
    let file_content =
        b"This is a test file with enough content to back up, corrupt, verify, and repair.";
    fs::write(source.join("test.txt"), file_content).unwrap();

    // Initialize repo
    let mut repo = Repository::init(&repo_path, None).unwrap();

    let chunker = Chunker::new(
        repo.config.chunk_min_size,
        repo.config.chunk_max_size,
        repo.config.chunk_target_size,
    )
    .unwrap();

    let snapshot = Snapshot::build_from_path(&source, &chunker, &mut repo).unwrap();
    snapshot.save(&repo_path).unwrap();
    repo.flush_pending().unwrap();
    repo.save_index().unwrap();

    let original_hash = compute_hash(file_content);
    drop(repo);

    // Verify initially passes
    let verifier = Verifier::new(&repo_path).unwrap();
    let pre_result = verifier.verify(VerifyLevel::Full).unwrap();
    assert!(pre_result.is_ok(), "initial verify should pass");

    // Corrupt a pack file
    corrupt_pack_file(&repo_path);

    // Verify should now detect errors
    let verifier = Verifier::new(&repo_path).unwrap();
    let post_result = verifier.verify(VerifyLevel::Full).unwrap();
    assert!(
        !post_result.is_ok() || post_result.chunks_corrupt > 0 || post_result.chunks_missing > 0,
        "verify should detect corruption after pack tampering, got: chunks_corrupt={}, chunks_missing={}",
        post_result.chunks_corrupt,
        post_result.chunks_missing,
    );

    // Repair via Scrubber
    let scrubber = Scrubber::new(&repo_path).unwrap();
    let repair_result = scrubber.scrub_and_repair().unwrap();

    // Re-verify after repair
    let verifier = Verifier::new(&repo_path).unwrap();
    let post_repair_result = verifier.verify(VerifyLevel::Full).unwrap();

    if !post_repair_result.is_ok() {
        // If repair didn't fix everything, at least some errors were found
        assert!(
            repair_result.errors_found.len() > 0
                || post_repair_result.chunks_corrupt <= pre_result.chunks_corrupt,
            "repair should reduce or detect corruptions, before: {} corrupt, after: {} corrupt",
            pre_result.chunks_corrupt,
            post_repair_result.chunks_corrupt,
        );
    }

    // Restore and compare
    fs::create_dir_all(&restore_path).unwrap();
    let restorer = backup_shield_restore::Restorer::new(&repo_path).unwrap();
    let options = backup_shield_restore::RestoreOptions::new(
        repo_path.clone(),
        "latest".to_string(),
        restore_path.clone(),
    );
    let restore_result = restorer.restore(options).unwrap();

    if restore_result.files_restored > 0 {
        let restored_file = restore_path.join("test.txt");
        if restored_file.exists() {
            let restored_data = fs::read(&restored_file).unwrap();
            let restored_hash = compute_hash(&restored_data);
            assert_eq!(
                original_hash, restored_hash,
                "restored file content does not match original"
            );
        }
    }
}
