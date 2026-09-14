fn main() {
    for path in ["../source-lock.json", "../build.py", "../vendor/risc0"] {
        println!("cargo:rerun-if-changed={path}");
    }
    let status = std::process::Command::new("python3")
        .args(["../build.py", "check"])
        .status()
        .expect("Python 3 required for exact source-lock validation");
    assert!(status.success(), "C3 upstream source pin validation failed");
}
