// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=CORROSION_BUILD_DIR");
    println!("cargo:rerun-if-changed=../../src/lotus_v2/vendor/libmdbx/mdbx.c");
    println!("cargo:rerun-if-changed=../../src/lotus_v2/vendor/libmdbx/mdbx.h");
    println!("cargo:rerun-if-changed=../../src/lotus_v2/vendor/libmdbx/mdbx_batch.c");
    println!("cargo:rerun-if-changed=../../src/lotus_v2/vendor/libmdbx/mdbx_batch.h");

    if env::var("CORROSION_BUILD_DIR").is_ok() {
        // When built via CMake Corrosion, the CMake `lotus_v2_mdbx` static library
        // target is already linked into the final binary.
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let mdbx_dir = manifest_dir.join("../../src/lotus_v2/vendor/libmdbx");
    let mdbx_c = mdbx_dir.join("mdbx.c");
    let mdbx_batch_c = mdbx_dir.join("mdbx_batch.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let obj_path = out_dir.join("mdbx.o");
    let batch_obj_path = out_dir.join("mdbx_batch.o");
    let lib_path = out_dir.join("libmdbx_chronik.a");

    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    for (src, obj) in [(&mdbx_c, &obj_path), (&mdbx_batch_c, &batch_obj_path)] {
        let status = Command::new(&cc)
            .arg("-c")
            .arg("-O3")
            .arg("-std=gnu11")
            .arg("-fPIC")
            .arg("-DNDEBUG")
            .arg("-DMDBX_BUILD_SHARED_LIBRARY=0")
            .arg("-DMDBX_WITHOUT_MSVC_CRT=0")
            .arg("-DMDBX_MMAP_NEEDS_JOLT=0")
            .arg("-Wno-everything")
            .arg("-I")
            .arg(&mdbx_dir)
            .arg(src)
            .arg("-o")
            .arg(obj)
            .status()
            .expect("Failed to execute C compiler for libmdbx");
        assert!(status.success(), "Failed to compile {:?} in build.rs", src);
    }

    let _ = std::fs::remove_file(&lib_path);
    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let status = Command::new(&ar)
        .arg("rcs")
        .arg(&lib_path)
        .arg(&obj_path)
        .arg(&batch_obj_path)
        .status()
        .expect("Failed to execute ar for libmdbx");
    assert!(status.success(), "Failed to archive libmdbx_chronik.a");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=mdbx_chronik");
}
