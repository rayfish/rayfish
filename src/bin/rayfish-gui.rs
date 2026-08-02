//! Console-free Windows launcher for the local Rayfish browser UI.
//!
//! The main `ray` binary intentionally remains a console CLI so scripts and
//! service diagnostics keep their stdout/stderr contract. Explorer shortcuts
//! should target this small GUI-subsystem launcher instead.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ray =
        std::env::current_exe()?.with_file_name(if cfg!(windows) { "ray.exe" } else { "ray" });
    let mut command = Command::new(ray);
    command.arg("gui");
    #[cfg(windows)]
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    // Keep the launcher alive with the server so the desktop process has a
    // normal lifetime and closing the server also closes the shortcut process.
    command.status()?;
    Ok(())
}
