// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CORROSION_BUILD_DIR");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../src/lotus_v2/vendor/libmdbx/mdbx.c");
    println!("cargo:rerun-if-changed=../../src/lotus_v2/vendor/libmdbx/mdbx.h");

    if env::var("CORROSION_BUILD_DIR").is_ok() {
        // When built via CMake Corrosion, the CMake `lotus_v2_mdbx` static
        // library target is linked into the final binary.
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"),
    );
    let mdbx_dir = manifest_dir
        .join("../../src/lotus_v2/vendor/libmdbx");
    let mdbx_c = mdbx_dir.join("mdbx.c");
    let obj_path = out_dir.join("mdbx.o");
    let lib_path = out_dir.join("libmdbx.a");

    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let status = Command::new(&cc)
        .arg("-c")
        .arg("-O2")
        .arg("-DNDEBUG")
        .arg("-fPIC")
        .arg("-std=gnu11")
        .arg("-DMDBX_BUILD_FLAGS=\"-O2 -DNDEBUG\"")
        .arg("-Wno-unused-parameter")
        .arg("-Wno-deprecated-declarations")
        .arg("-I")
        .arg(&mdbx_dir)
        .arg(&mdbx_c)
        .arg("-o")
        .arg(&obj_path)
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke C compiler {}: {}", cc, e));
    assert!(status.success(), "compiling vendor/libmdbx/mdbx.c failed");

    let _ = std::fs::remove_file(&lib_path);
    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let ar_status = Command::new(&ar)
        .arg("crs")
        .arg(&lib_path)
        .arg(&obj_path)
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke archiver {}: {}", ar, e));
    assert!(ar_status.success(), "archiving libmdbx.a failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=mdbx");
}
