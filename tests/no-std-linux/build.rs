//! Link configuration for the libc-free Linux userspace fixture.

use std::env;

fn main() {
    let root = env::var("CARGO_MANIFEST_DIR").expect("manifest directory");
    let script = format!("{root}/link.ld");
    let bin = "desenredo-no-std-linux";

    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rustc-link-arg-bin={bin}=-nostartfiles");
    println!("cargo:rustc-link-arg-bin={bin}=-nodefaultlibs");
    println!("cargo:rustc-link-arg-bin={bin}=-static");
    println!("cargo:rustc-link-arg-bin={bin}=-no-pie");
    println!("cargo:rustc-link-arg-bin={bin}=-Wl,-e,_start");
    println!("cargo:rustc-link-arg-bin={bin}=-Wl,-T,{script}");
}
