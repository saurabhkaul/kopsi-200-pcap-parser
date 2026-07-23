use std::process::Command;

pub fn parser_output(args: &[&str]) -> Vec<u8> {
    let output = Command::new(env!("CARGO_BIN_EXE_kopsi-200-pcap-parser"))
        .args(args)
        .output()
        .expect("should run parser binary");

    assert!(
        output.status.success(),
        "parser failed with status {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    output.stdout
}
