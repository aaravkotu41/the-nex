fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    embed_tray_icon();
}

/// Embeds icons/icon.ico as icon resource 1, which `--tray` loads for the notification area.
#[cfg(not(windows))]
fn embed_tray_icon() {
    // shortcut: embed-resource is only a Windows-host build-dependency in Cargo.toml, so
    // Windows targets cross-built from other hosts get no icon; make it unconditional to fix.
}

#[cfg(windows)]
fn embed_tray_icon() {
    use std::path::PathBuf;

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    );
    let icon = manifest_dir
        .join("..")
        .join("the-nex-gui")
        .join("icons")
        .join("icon.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    // The build-script cfg is the HOST; the target is what matters.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    assert!(
        icon.is_file(),
        "{} is missing; run `python scripts/gen_icons.py`",
        icon.display()
    );
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let script = out_dir.join("the-nex.rc");
    let escaped = icon.display().to_string().replace('\\', "\\\\");
    std::fs::write(&script, format!("1 ICON \"{escaped}\"\n")).expect("write the-nex.rc");
    if let Err(error) = embed_resource::compile(&script, embed_resource::NONE).manifest_optional() {
        panic!("embedding the tray icon failed: {error}");
    }
}
