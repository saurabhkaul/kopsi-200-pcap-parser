use std::path::PathBuf;

/// Path to the KOSPI 200 PCAP fixture used across integration tests.
pub fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test/fixtures/mdf-kospi200.20110216-0.pcap 2")
}
