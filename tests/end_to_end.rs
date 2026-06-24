use anyhow::Result;
use backup_shield_core::chunker::Chunker;
use backup_shield_core::repository::Repository;
use backup_shield_core::snapshot::{list_snapshots, Snapshot};
use backup_shield_restore::{RestoreOptions, Restorer};
use backup_shield_verify::{Verifier, VerifyLevel};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn create_test_files(source: &Path) {
    fs::create_dir_all(source.join("subdir")).unwrap();

    fs::write(source.join("hello.txt"), b"Hello, BackupShield!").unwrap();

    let binary_data: Vec<u8> = (0..255).chain((0..255).rev()).collect();
    fs::write(source.join("binary.bin"), &binary_data).unwrap();

    fs::write(source.join("empty.dat"), b"").unwrap();

    fs::write(source.join("file with spaces.txt"), b"spaces in name").unwrap();

    fs::write(source.join("déjà vu.txt"), "déjà vu content".as_bytes()).unwrap();

    fs::write(source.join("subdir").join("nested.txt"), b"nested file").unwrap();
}

fn hash_file(path: &Path) -> String {
    let data = fs::read(path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hex::encode(hasher.finalize())
}

fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(dir) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            files.push(entry.path().strip_prefix(dir).unwrap().to_path_buf());
        }
    }
    files.sort();
    files
}

#[test]
fn test_end_to_end_backup_verify_restore() -> Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("source");
    let repo_path = root.path().join("repo");
    let restore_path = root.path().join("restore");

    create_test_files(&source);

    let mut repo = Repository::init(&repo_path, None)?;
    let snapshot_id = {
        let chunker = Chunker::new(
            repo.config.chunk_min_size,
            repo.config.chunk_max_size,
            repo.config.chunk_target_size,
        )?;

        let snapshot = Snapshot::build_from_path(&source, &chunker, &mut repo)?;
        let id = snapshot.id.clone();
        snapshot.save(&repo_path)?;
        repo.flush_pending()?;
        repo.save_index()?;
        id
    };
    drop(repo);

    let snapshots = list_snapshots(&repo_path)?;
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].id, snapshot_id);

    let verifier = Verifier::new(&repo_path)?;
    let result = verifier.verify(VerifyLevel::Full)?;
    assert!(result.is_ok(), "verify failed: {:?}", result.errors);

    fs::create_dir_all(&restore_path)?;
    let restorer = Restorer::new(&repo_path)?;
    let options = RestoreOptions::new(
        repo_path.clone(),
        "latest".to_string(),
        restore_path.clone(),
    );
    let restore_result = restorer.restore(options)?;
    assert_eq!(
        restore_result.errors.len(),
        0,
        "restore had errors: {:?}",
        restore_result.errors
    );

    let original_files = collect_files(&source);
    let restored_files = collect_files(&restore_path);

    assert!(!original_files.is_empty(), "no source files to compare");
    assert_eq!(
        original_files.len(),
        restored_files.len(),
        "file count mismatch: original={:?} restored={:?}",
        original_files,
        restored_files,
    );

    for rel_path in &original_files {
        let orig_path = source.join(rel_path);
        let rest_path = restore_path.join(rel_path);
        assert!(rest_path.exists(), "restored file missing: {:?}", rest_path);
        assert_eq!(
            hash_file(&orig_path),
            hash_file(&rest_path),
            "content mismatch for {:?}",
            rel_path,
        );
    }

    Ok(())
}
