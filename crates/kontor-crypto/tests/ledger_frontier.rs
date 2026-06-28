//! Equivalence tests for the incremental [`LedgerFrontier`] against the from-scratch
//! [`aggregate_root_from_files`]. The frontier is only useful if its root is
//! byte-identical to a full rebuild over the same contiguous, append-only slots — these
//! tests pin that across every count up to a few power-of-two boundaries (where the
//! aggregated tree depth grows), plus mixed depths and persisted-state round-trips.

use kontor_crypto::{aggregate_root_from_files, FieldElement, LedgerFrontier};

/// A distinct, deterministic file root for index `i`.
fn root_for(i: u64) -> FieldElement {
    FieldElement::from(1_000_003u64 + i)
}

/// Mixed leaf depths so the test exercises non-trivial `rc = commit(root, depth)` inputs,
/// not just a constant depth.
fn depth_for(i: u64) -> usize {
    (i % 7) as usize
}

#[test]
fn frontier_matches_aggregate_root_across_counts() {
    // Empty ledger first: frontier root must equal the from-scratch empty root.
    let frontier = LedgerFrontier::new();
    assert_eq!(
        frontier.root(),
        aggregate_root_from_files(&[]).expect("empty aggregate_root"),
        "empty-ledger root mismatch"
    );

    // Walk counts 1..=300, which crosses the depth-growth boundaries at 2, 4, 8, …, 256.
    let mut frontier = LedgerFrontier::new();
    let mut files: Vec<(FieldElement, usize, usize)> = Vec::new();
    for i in 0u64..300 {
        let (root, depth) = (root_for(i), depth_for(i));
        frontier.append(root, depth);
        files.push((root, depth, i as usize));

        let expected = aggregate_root_from_files(&files).expect("aggregate_root_from_files");
        assert_eq!(
            frontier.root(),
            expected,
            "frontier root diverged from aggregate_root at count {}",
            i + 1
        );
        assert_eq!(frontier.count(), i + 1);
        // Structural invariant: one peak per set bit of the count.
        assert_eq!(frontier.peaks().len(), (i + 1).count_ones() as usize);
    }
}

#[test]
fn frontier_from_parts_roundtrips_and_validates() {
    let mut frontier = LedgerFrontier::new();
    for i in 0u64..37 {
        frontier.append(root_for(i), depth_for(i));
    }

    // Persist → reconstruct → identical state and root.
    let rebuilt = LedgerFrontier::from_parts(frontier.count(), frontier.peaks().to_vec())
        .expect("valid parts reconstruct");
    assert_eq!(rebuilt, frontier);
    assert_eq!(rebuilt.root(), frontier.root());

    // A peak count that doesn't match the set bits of `count` is rejected.
    assert!(LedgerFrontier::from_parts(0b101, vec![root_for(0)]).is_err());
    assert!(LedgerFrontier::from_parts(0, vec![root_for(0)]).is_err());
}

#[test]
fn frontier_append_is_incremental_not_order_dependent_on_slots() {
    // Appending in slot order must equal a fresh full rebuild that lists files in any
    // order (aggregate_root sorts by slot internally), confirming the frontier's
    // low-index-left fold matches the canonical slot layout.
    let mut frontier = LedgerFrontier::new();
    let mut files: Vec<(FieldElement, usize, usize)> = Vec::new();
    for i in 0u64..16 {
        frontier.append(root_for(i), depth_for(i));
        files.push((root_for(i), depth_for(i), i as usize));
    }
    let mut shuffled = files.clone();
    shuffled.reverse();
    assert_eq!(
        frontier.root(),
        aggregate_root_from_files(&shuffled).expect("aggregate over reversed input")
    );
}
