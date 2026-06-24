use backup_shield_core::chunker::Chunker;
use backup_shield_core::pack::compact_packs;
use backup_shield_core::repository::Repository;
use backup_shield_core::snapshot::{list_snapshots, prune_snapshots, Snapshot};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn init_repo(path: &Path) -> Repository {
    Repository::init(path, None).unwrap()
}

fn make_snapshot(
    repo_path: &Path,
    repo: &mut Repository,
    chunker: &Chunker,
    file_content: &[u8],
    timestamp: DateTime<Utc>,
    label: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join(format!("{}.txt", label));
    fs::write(&file_path, file_content).unwrap();

    let mut snapshot = Snapshot::build_from_path(&file_path, chunker, repo).unwrap();
    snapshot.timestamp = timestamp;
    snapshot.save(repo_path).unwrap();
}

fn count_snapshots(repo_path: &Path) -> usize {
    list_snapshots(repo_path).unwrap().len()
}

#[test]
fn test_daily_weekly_monthly_retention() {
    let root = tempfile::tempdir().unwrap();
    let repo_path = root.path().join("repo");
    let mut repo = init_repo(&repo_path);

    let chunker = Chunker::new(
        repo.config.chunk_min_size,
        repo.config.chunk_max_size,
        repo.config.chunk_target_size,
    )
    .unwrap();

    let now = Utc::now();

    // Create snapshots at different dates:
    // - 2 from today
    // - 2 from 2 days ago (same day)
    // - 1 from last week
    // - 1 from last month
    let timestamps = vec![
        (now - Duration::days(35), "monthly_old"),
        (now - Duration::days(9), "weekly_old"),
        (now - Duration::days(2), "daily_old_a"),
        (now - Duration::days(2) + Duration::hours(1), "daily_old_b"),
        (now - Duration::hours(2), "recent_a"),
        (now - Duration::hours(1), "recent_b"),
    ];

    for (ts, label) in &timestamps {
        make_snapshot(
            &repo_path,
            &mut repo,
            &chunker,
            format!("content_{}", label).as_bytes(),
            *ts,
            label,
        );
    }

    repo.flush_pending().unwrap();
    repo.save_index().unwrap();
    drop(repo);

    assert_eq!(count_snapshots(&repo_path), 6);

    // Keep 1 daily, 1 weekly, 1 monthly
    let removed = prune_snapshots(&repo_path, 1, 1, 1).unwrap();
    assert!(!removed.is_empty(), "expected some snapshots to be pruned");

    let remaining = list_snapshots(&repo_path).unwrap();
    assert!(
        remaining.len() < 6,
        "expected some snapshots to be removed, got {} remaining",
        remaining.len()
    );
    assert!(
        !remaining.is_empty(),
        "expected at least 1 snapshot to remain (min_snapshots not set), got {}",
        remaining.len()
    );
}

#[test]
fn test_compact_packs_removes_orphans() {
    let root = tempfile::tempdir().unwrap();
    let repo_path = root.path().join("repo");
    let mut repo = init_repo(&repo_path);

    // Store some chunks — they will be flushed to packs
    let hash_a = repo.store_chunk(b"chunk a content here").unwrap();
    let hash_b = repo.store_chunk(b"chunk b content here").unwrap();
    let hash_c = repo.store_chunk(b"chunk c content here").unwrap();
    repo.flush_pending().unwrap();
    repo.save_index().unwrap();
    drop(repo);

    // Remove chunk_a and chunk_c from index to create orphaned data in packs
    let mut repo = Repository::open(&repo_path).unwrap();
    assert_eq!(repo.index.len(), 3);
    repo.remove_chunk(&hash_a).unwrap();
    repo.remove_chunk(&hash_c).unwrap();
    repo.save_index().unwrap();
    assert_eq!(repo.index.len(), 1);
    drop(repo);

    // Compact with only hash_b as live
    let mut live_hashes = HashSet::new();
    live_hashes.insert(hash_b);
    let compact_result = compact_packs(&repo_path, &live_hashes, 4096).unwrap();
    assert!(compact_result.chunks_discarded >= 2);
    assert!(compact_result.chunks_kept >= 1);
    assert!(compact_result.bytes_freed > 0);
    assert!(compact_result.packs_after <= compact_result.packs_before);
}

#[test]
fn test_auto_prune_storage_limit() {
    let root = tempfile::tempdir().unwrap();
    let repo_path = root.path().join("repo");
    let mut repo = init_repo(&repo_path);

    // Set a very small max_size (200 bytes) to trigger auto-prune
    repo.config.max_size = 200;
    repo.config.min_snapshots = 1;
    repo.config.save(&repo_path).unwrap();

    let chunker = Chunker::new(
        repo.config.chunk_min_size,
        repo.config.chunk_max_size,
        repo.config.chunk_target_size,
    )
    .unwrap();

    let now = Utc::now();

    // Create 3 snapshots with different content to use up space
    for i in 0..3 {
        let ts = now - Duration::hours(i);
        let content = format!(
            "A lot of padding data to exceed the tiny 200 byte limit! Iteration {}",
            i
        );
        make_snapshot(
            &repo_path,
            &mut repo,
            &chunker,
            content.as_bytes(),
            ts,
            &format!("snap_{}", i),
        );
    }

    repo.flush_pending().unwrap();
    repo.save_index().unwrap();
    drop(repo);

    // Reopen and check storage limit
    let repo2 = Repository::open(&repo_path).unwrap();
    let to_prune = repo2.check_storage_limit();
    assert!(to_prune.is_some(), "expected storage limit to trigger");
    assert!(
        !to_prune.unwrap().is_empty(),
        "expected at least one snapshot to prune"
    );
    drop(repo2);
}
