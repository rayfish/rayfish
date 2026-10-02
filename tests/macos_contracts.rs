#[test]
fn xcode_marketing_version_matches_cargo_package() {
    let cargo_version = env!("CARGO_PKG_VERSION");
    let marketing_version = cargo_version
        .split_once(['-', '+'])
        .map_or(cargo_version, |(version, _)| version);
    let expected = format!("MARKETING_VERSION: \"{marketing_version}\"");

    assert!(
        include_str!("../macos/project.yml")
            .lines()
            .any(|line| line.trim() == expected),
        "macos/project.yml must contain {expected}"
    );
}
