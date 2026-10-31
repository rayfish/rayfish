use anyhow::Result;
use eframe::egui::{IconData, ViewportBuilder};

pub(crate) fn options() -> Result<eframe::NativeOptions> {
    let icon = image::load_from_memory(include_bytes!(
        "../../macos/Rayfish/Assets.xcassets/AppIcon.appiconset/icon-256.png"
    ))?
    .into_rgba8();
    let (width, height) = icon.dimensions();
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([820.0, 560.0])
            .with_icon(IconData {
                rgba: icon.into_raw(),
                width,
                height,
            }),
        renderer: eframe::Renderer::Wgpu,
        centered: true,
        ..Default::default()
    };
    Ok(options)
}
