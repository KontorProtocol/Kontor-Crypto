//! Criterion benchmark harness for Kontor PoR
//!
//! This file coordinates all benchmark modules and registers them with criterion.
//! Run with: cargo bench
//! Run with CodSpeed: cargo codspeed run

use codspeed_criterion_compat::criterion_main;

mod e2e_scenarios;
mod file_preparation;
mod primitives;
mod proving;
mod verification;

criterion_main! {
    primitives::benches,
    file_preparation::benches,
    proving::benches,
    verification::benches,
    e2e_scenarios::benches,
}
