#![cfg(windows)]

//! Windows adapter contracts that do not require Administrator, Wintun, or a
//! live mesh. Privileged MSI/service/DNS tests stay in the manual lane.

use std::fs;

#[test]
fn console_process_does_not_claim_windows_service_dispatch() {
    assert!(
        !rayfish::windows_service::run_if_service()
            .expect("console invocation should return the dispatcher fallback")
    );
}

/// `ray.exe` asks for the stack a debug build of it needs.
///
/// Windows reads the main thread's stack out of the PE header and gives it 1 MiB
/// by default. Building the clap command tree does not fit in that unoptimized,
/// so before build.rs raised the reserve every command, `--version` included,
/// died with `0xC00000FD` before parsing an argument. Read the header rather
/// than the running process: this harness is a test target and keeps the default.
#[test]
fn the_binary_reserves_a_stack_it_can_build_its_command_tree_on() {
    let image = fs::read(env!("CARGO_BIN_EXE_ray")).expect("read ray.exe");

    // Every read is bounds-checked with a message: a truncated or non-PE image
    // should say which field ran off the end, not panic on a slice index.
    let field = |at: usize, len: usize, what: &str| -> Vec<u8> {
        image
            .get(at..at + len)
            .unwrap_or_else(|| panic!("{what} runs past the end of a {}-byte image", image.len()))
            .to_vec()
    };

    // The DOS stub points at the PE signature; the optional header follows the
    // 4-byte signature and the 20-byte COFF header, and holds the stack reserve
    // at offset 72 in its PE32+ form.
    let e_lfanew = field(0x3c, 4, "e_lfanew");
    let pe = u32::from_le_bytes(e_lfanew.try_into().expect("4 bytes")) as usize;
    assert_eq!(field(pe, 4, "PE signature"), b"PE\0\0", "not a PE image");
    let optional = pe + 24;
    let magic = u16::from_le_bytes(
        field(optional, 2, "optional header magic")
            .try_into()
            .expect("2 bytes"),
    );
    assert_eq!(magic, 0x20b, "not a 64-bit image");
    let reserve = u64::from_le_bytes(
        field(optional + 72, 8, "SizeOfStackReserve")
            .try_into()
            .expect("8 bytes"),
    );

    assert!(
        reserve >= 8 * 1024 * 1024,
        "stack reserve is {reserve} bytes"
    );
}
