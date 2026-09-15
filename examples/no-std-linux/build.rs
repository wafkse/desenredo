//! Link configuration for the static Linux userspace example.

use std::env;

/// Configures a libc-free static executable with a custom process entry point.
fn main() {
    let root = env::var("CARGO_MANIFEST_DIR").expect("manifest directory");
    let script = format!("{root}/link.ld");
    let bin = "desenredo-no-std-worker";

    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=src/start.S");
    println!("cargo:rustc-link-arg-bin={bin}=-nostartfiles");
    println!("cargo:rustc-link-arg-bin={bin}=-nodefaultlibs");
    println!("cargo:rustc-link-arg-bin={bin}=-static");
    println!("cargo:rustc-link-arg-bin={bin}=-no-pie");
    println!("cargo:rustc-link-arg-bin={bin}=-Wl,-e,_start");
    println!("cargo:rustc-link-arg-bin={bin}=-Wl,-T,{script}");
}
