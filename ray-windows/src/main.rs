#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod backend;
#[cfg(windows)]
mod controls;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod forms;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod model;

#[cfg(not(windows))]
fn main() {
    eprintln!("rayfish-app is only available on Windows");
}

#[cfg(windows)]
fn main() {
    if let Err(error) = app::run() {
        app::show_error(&format!("Rayfish could not start.\n\n{error:#}"));
    }
}
