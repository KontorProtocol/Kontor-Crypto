//! Criterion benchmark harness for Kontor PoR
//!
//! This file coordinates all benchmark modules and registers them with criterion.
//! Run with: cargo bench

use criterion::criterion_main;

mod primitives;
mod file_preparation;
mod proving;
mod verification;
mod e2e_scenarios;

criterion_main! {
    primitives::benches,
    file_preparation::benches,
    proving::benches,
    verification::benches,
    e2e_scenarios::benches,
}

