#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod backend;
mod forms;
#[cfg_attr(not(windows), allow(dead_code))]
mod model;
#[cfg(any(not(windows), test))]
#[cfg_attr(windows, allow(dead_code))]
mod preview;
#[cfg(windows)]
mod service;
#[cfg_attr(not(windows), allow(dead_code))]
mod ui;
mod window;

#[cfg(not(windows))]
fn main() {
    use std::path::PathBuf;

    let args = std::env::args().collect::<Vec<_>>();
    if let Some(index) = args.iter().position(|arg| arg == "--preview-screenshot")
        && let Some(path) = args.get(index + 1)
    {
        let page = if args.iter().any(|arg| arg == "--settings") {
            ui::Page::Settings
        } else if args.iter().any(|arg| arg == "--devices") {
            ui::Page::Devices
        } else {
            ui::Page::Networks
        };
        if let Err(error) = preview::run(
            PathBuf::from(path),
            args.iter().any(|arg| arg == "--populated"),
            page,
            if args.iter().any(|arg| arg == "--loading") {
                preview::PreviewState::Loading
            } else if args.iter().any(|arg| arg == "--unavailable") {
                preview::PreviewState::Unavailable
            } else if args.iter().any(|arg| arg == "--stale") {
                preview::PreviewState::Stale
            } else if args.iter().any(|arg| arg == "--joining") {
                preview::PreviewState::Joining
            } else if args.iter().any(|arg| arg == "--reconnecting") {
                preview::PreviewState::Reconnecting
            } else {
                preview::PreviewState::Normal
            },
        ) {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    } else {
        eprintln!("rayfish-app is only available on Windows");
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = app::run() {
        app::show_error(&format!("Rayfish could not start.\n\n{error:#}"));
    }
}
