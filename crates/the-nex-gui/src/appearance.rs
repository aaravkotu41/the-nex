//! Per-user appearance for the desktop app: wallpaper source plus the glass theme sliders.
//!
//! Stored in the app's own config folder (`settings.json`) and wallpaper images in its data
//! folder (`wallpapers/`), not in the service's admin-only `settings.json` under ProgramData,
//! so changing the look never raises an administrator prompt. Saved images are served to the
//! webview through the `wallpaper://` URI scheme.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::http::{header, Request, Response, StatusCode};
use tauri::{AppHandle, Manager, Runtime};
use url::Url;

pub const WALLPAPER_SCHEME: &str = "wallpaper";
const SETTINGS_FILE: &str = "settings.json";
const WALLPAPER_DIR: &str = "wallpapers";
const WALLPAPER_PREFIX: &str = "wallpaper-";
const MAX_WALLPAPER_BYTES: usize = 25 * 1024 * 1024;
const MAX_HTML_BYTES: u64 = 2 * 1024 * 1024;
const MAX_URL_LEN: usize = 2048;
const KEEP_WALLPAPERS: usize = 8;
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const USER_AGENT: &str = "Mozilla/5.0 (compatible; TheNex/0.2; wallpaper fetch)";

/// Built-in wallpapers, drawn by the frontend (no image files).
pub const PRESETS: &[&str] = &["matte", "crimson", "cyberhex"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Appearance {
    /// `preset:<id>`, `url:<http(s) image URL>` or `file:<saved wallpaper name>`.
    pub wallpaper_source: String,
    /// Readability scrim over the wallpaper, 0.0 – 0.9.
    pub bg_dim: f64,
    /// Card backdrop blur in pixels, 0 – 24.
    pub card_blur: f64,
    /// Card background opacity, 0.30 – 0.95.
    pub card_alpha: f64,
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            wallpaper_source: "preset:matte".to_string(),
            bg_dim: 0.65,
            card_blur: 14.0,
            card_alpha: 0.72,
        }
    }
}

fn finite_or(value: f64, fallback: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        fallback
    }
}

impl Appearance {
    /// Clamps every value into range and replaces an unknown or unsafe source with the default.
    pub fn sanitized(self) -> Self {
        let defaults = Self::default();
        let wallpaper_source = if is_valid_source(&self.wallpaper_source) {
            self.wallpaper_source
        } else {
            defaults.wallpaper_source
        };
        Self {
            wallpaper_source,
            bg_dim: finite_or(self.bg_dim, defaults.bg_dim).clamp(0.0, 0.9),
            card_blur: finite_or(self.card_blur, defaults.card_blur).clamp(0.0, 24.0),
            card_alpha: finite_or(self.card_alpha, defaults.card_alpha).clamp(0.3, 0.95),
        }
    }
}

pub fn is_valid_source(source: &str) -> bool {
    if let Some(id) = source.strip_prefix("preset:") {
        return PRESETS.contains(&id);
    }
    if let Some(name) = source.strip_prefix("file:") {
        return is_wallpaper_name(name);
    }
    if let Some(url) = source.strip_prefix("url:") {
        return url.len() <= MAX_URL_LEN && web_url(url).is_some();
    }
    false
}

fn web_url(text: &str) -> Option<Url> {
    let url = Url::parse(text.trim()).ok()?;
    matches!(url.scheme(), "http" | "https").then_some(url)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Jpeg,
    Gif,
    Webp,
}

impl ImageKind {
    /// Identifies an image by its magic bytes; the file name or extension is never trusted.
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Self::Png)
        } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            Some(Self::Jpeg)
        } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
            Some(Self::Gif)
        } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            Some(Self::Webp)
        } else {
            None
        }
    }

    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_ascii_lowercase().as_str() {
            "png" => Some(Self::Png),
            "jpg" | "jpeg" => Some(Self::Jpeg),
            "gif" => Some(Self::Gif),
            "webp" => Some(Self::Webp),
            _ => None,
        }
    }

    /// Image type implied by a URL path's last segment (`.../photo.JPG` -> Jpeg).
    pub fn from_url_path(path: &str) -> Option<Self> {
        let last = path.rsplit('/').next()?;
        let (_, ext) = last.rsplit_once('.')?;
        Self::from_extension(ext)
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Gif => "gif",
            Self::Webp => "webp",
        }
    }

    fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
        }
    }
}

/// Names this app gives saved wallpapers: `wallpaper-<timestamp>[-n].<png|jpg|gif|webp>`.
/// Anything else (path separators, `..`, other extensions) is refused.
pub fn is_wallpaper_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(WALLPAPER_PREFIX) else {
        return false;
    };
    let Some((stem, ext)) = rest.split_once('.') else {
        return false;
    };
    name.len() <= 64
        && !stem.is_empty()
        && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && ImageKind::from_extension(ext).is_some()
}

pub fn load_appearance(path: &Path) -> Appearance {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|root| root.get("appearance").cloned())
        .and_then(|value| serde_json::from_value::<Appearance>(value).ok())
        .unwrap_or_default()
        .sanitized()
}

/// Writes `appearance` into the `appearance` key, keeping any other keys in the file.
pub fn store_appearance(path: &Path, appearance: &Appearance) -> io::Result<()> {
    let mut root = fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(|value| value.is_object())
        .unwrap_or_else(|| serde_json::json!({}));
    root["appearance"] = serde_json::to_value(appearance).map_err(io::Error::other)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let staging = path.with_extension("json.tmp");
    fs::write(
        &staging,
        serde_json::to_vec_pretty(&root).map_err(io::Error::other)?,
    )?;
    fs::rename(&staging, path)
}

/// Saves image bytes under a fresh name and returns that name. Keeps the newest few.
pub fn store_wallpaper(dir: &Path, bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_WALLPAPER_BYTES {
        return Err(format!(
            "images up to {} MB are supported",
            MAX_WALLPAPER_BYTES / (1024 * 1024)
        ));
    }
    let kind = ImageKind::detect(bytes)
        .ok_or_else(|| "that is not a PNG, JPEG, WEBP or GIF image".to_string())?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // Fixed-width nanosecond stamps: alphabetical order is chronological order (see pruning).
    let mut stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    let mut name = format!("{WALLPAPER_PREFIX}{stamp:020}.{}", kind.extension());
    while dir.join(&name).exists() {
        stamp += 1;
        name = format!("{WALLPAPER_PREFIX}{stamp:020}.{}", kind.extension());
    }
    fs::write(dir.join(&name), bytes).map_err(|e| format!("{}: {e}", dir.display()))?;
    prune_wallpapers(dir, &name);
    Ok(name)
}

fn prune_wallpapers(dir: &Path, keep: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| is_wallpaper_name(name))
        .collect();
    // Timestamped names sort chronologically; newest first.
    names.sort_unstable_by(|a, b| b.cmp(a));
    for name in names.into_iter().skip(KEEP_WALLPAPERS) {
        if name != keep {
            let _ = fs::remove_file(dir.join(name));
        }
    }
}

/// Response for `wallpaper://localhost/<name>` (`http://wallpaper.localhost/<name>` on Windows).
pub fn wallpaper_response(dir: Option<PathBuf>, uri_path: &str) -> Response<Vec<u8>> {
    let name = uri_path.trim_start_matches('/');
    let bytes = dir
        .filter(|_| is_wallpaper_name(name))
        .and_then(|dir| fs::read(dir.join(name)).ok());
    match bytes {
        Some(bytes) => {
            let mime = ImageKind::detect(&bytes)
                .map(ImageKind::mime)
                .unwrap_or("application/octet-stream");
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .header(header::CACHE_CONTROL, "max-age=31536000, immutable")
                .body(bytes)
                .unwrap_or_default()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Vec::new())
            .unwrap_or_default(),
    }
}

pub fn serve_wallpaper<R: Runtime>(
    app: &AppHandle<R>,
    request: &Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    wallpaper_response(wallpaper_dir(app).ok(), request.uri().path())
}

fn settings_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join(SETTINGS_FILE))
        .map_err(|e| e.to_string())
}

fn wallpaper_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join(WALLPAPER_DIR))
        .map_err(|e| e.to_string())
}

/// Attributes of one tag body (`name="v"`, `name='v'`, `name=v`, bare `name`), names lowercased.
fn parse_attributes(text: &str) -> Vec<(String, String)> {
    let bytes = text.as_bytes();
    let mut attrs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'/' | b'>')
        {
            i += 1;
        }
        if i == name_start {
            i += 1;
            continue;
        }
        let name = text[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let value = if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let value = &text[start..i];
                i += 1;
                value
            } else {
                let start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                &text[start..i]
            };
            attrs.push((name, value.to_string()));
        } else {
            attrs.push((name, String::new()));
        }
    }
    attrs
}

fn attribute<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(name, _)| name.as_str() == key)
        .map(|(_, value)| value.as_str())
}

fn decode_entities(text: &str) -> String {
    // `&amp;` last, so `&amp;quot;` stays the literal text `&quot;`.
    text.replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#x2F;", "/")
        .replace("&#x2f;", "/")
        .replace("&#47;", "/")
        .replace("&amp;", "&")
}

/// The page's share image: og:image (secure/url variants first), then twitter:image, then
/// `<link rel="image_src">`, resolved against `base` and limited to http(s).
pub fn extract_meta_image(html: &str, base: &Url) -> Option<String> {
    const KEYS: [&str; 6] = [
        "og:image:secure_url",
        "og:image:url",
        "og:image",
        "twitter:image",
        "twitter:image:src",
        "image_src",
    ];
    // ASCII lowercasing keeps every byte offset, so offsets found here index `html` too.
    let lower = html.to_ascii_lowercase();
    let mut found: Vec<(usize, String)> = Vec::new();
    let mut at = 0;
    while let Some(offset) = lower[at..].find('<') {
        let start = at + offset + 1;
        let Some(length) = lower[start..].find('>') else {
            break;
        };
        let end = start + length;
        at = end + 1;
        let tag = &lower[start..end];
        let is_meta = tag.starts_with("meta");
        let is_link = tag.starts_with("link");
        if !(is_meta || is_link) || !tag[4..].starts_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let attrs = parse_attributes(&html[start + 4..end]);
        let (key, value) = if is_meta {
            (
                attribute(&attrs, "property").or_else(|| attribute(&attrs, "name")),
                attribute(&attrs, "content"),
            )
        } else {
            (attribute(&attrs, "rel"), attribute(&attrs, "href"))
        };
        if let (Some(key), Some(value)) = (key, value) {
            let key = key.trim().to_ascii_lowercase();
            if let Some(priority) = KEYS.iter().position(|k| *k == key) {
                found.push((priority, value.to_string()));
            }
        }
    }
    found.sort_by_key(|(priority, _)| *priority);
    found.into_iter().find_map(|(_, value)| {
        let url = base.join(decode_entities(value.trim()).as_str()).ok()?;
        matches!(url.scheme(), "http" | "https").then(|| url.to_string())
    })
}

fn http_agent() -> Result<ureq::Agent, String> {
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("TLS is unavailable: {e}"))?;
    Ok(ureq::AgentBuilder::new()
        .tls_connector(Arc::new(tls))
        .timeout(HTTP_TIMEOUT)
        .redirects(5)
        .user_agent(USER_AGENT)
        .build())
}

fn describe(error: ureq::Error) -> String {
    match error {
        ureq::Error::Status(code, _) => format!("the site answered HTTP {code}"),
        ureq::Error::Transport(transport) => format!("could not reach the site: {transport}"),
    }
}

/// A direct image URL is returned as is; a web page is fetched and its share image returned.
pub fn resolve_image_url(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.len() > MAX_URL_LEN {
        return Err("that address is too long".to_string());
    }
    let url =
        web_url(input).ok_or_else(|| "enter a full http:// or https:// address".to_string())?;
    if ImageKind::from_url_path(url.path()).is_some() {
        return Ok(url.to_string());
    }
    let response = http_agent()?
        .get(url.as_str())
        .set(
            "Accept",
            "text/html,application/xhtml+xml,image/webp,image/png,image/jpeg;q=0.9,*/*;q=0.5",
        )
        .call()
        .map_err(describe)?;
    let page_url = Url::parse(response.get_url()).unwrap_or(url);
    if response
        .content_type()
        .to_ascii_lowercase()
        .starts_with("image/")
    {
        return Ok(page_url.to_string());
    }
    let mut html = Vec::new();
    response
        .into_reader()
        .take(MAX_HTML_BYTES)
        .read_to_end(&mut html)
        .map_err(|e| format!("could not read the page: {e}"))?;
    extract_meta_image(&String::from_utf8_lossy(&html), &page_url).ok_or_else(|| {
        "that page has no og:image or twitter:image to use as a wallpaper".to_string()
    })
}

fn download_image(url: &str) -> Result<Vec<u8>, String> {
    let url = web_url(url).ok_or_else(|| "not a web address".to_string())?;
    let response = http_agent()?
        .get(url.as_str())
        .set(
            "Accept",
            "image/webp,image/png,image/jpeg,image/gif;q=0.9,*/*;q=0.5",
        )
        .call()
        .map_err(describe)?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_WALLPAPER_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not download the image: {e}"))?;
    if bytes.len() > MAX_WALLPAPER_BYTES {
        return Err(format!(
            "images up to {} MB are supported",
            MAX_WALLPAPER_BYTES / (1024 * 1024)
        ));
    }
    Ok(bytes)
}

#[tauri::command]
pub fn get_appearance(app: AppHandle) -> Result<Appearance, String> {
    Ok(load_appearance(&settings_path(&app)?))
}

#[tauri::command]
pub fn save_appearance(app: AppHandle, appearance: Appearance) -> Result<Appearance, String> {
    let appearance = appearance.sanitized();
    let path = settings_path(&app)?;
    store_appearance(&path, &appearance).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(appearance)
}

#[tauri::command]
pub async fn resolve_wallpaper_url(url: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || resolve_image_url(&url))
        .await
        .map_err(|e| e.to_string())?
}

/// Downloads an image URL into the wallpaper folder so it survives restarts and works offline.
#[tauri::command]
pub async fn download_wallpaper(app: AppHandle, url: String) -> Result<String, String> {
    let dir = wallpaper_dir(&app)?;
    tauri::async_runtime::spawn_blocking(move || store_wallpaper(&dir, &download_image(&url)?))
        .await
        .map_err(|e| e.to_string())?
}

/// Raw image bytes from the file picker (sent as an ArrayBuffer, not JSON).
#[tauri::command]
pub fn save_wallpaper_file(
    app: AppHandle,
    request: tauri::ipc::Request<'_>,
) -> Result<String, String> {
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("expected the image file's bytes".to_string());
    };
    store_wallpaper(&wallpaper_dir(&app)?, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("thenex-appearance-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn png() -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes
    }

    #[test]
    fn sanitizing_clamps_values_and_rejects_unknown_sources() {
        let wild = Appearance {
            wallpaper_source: "file:../../secrets.png".to_string(),
            bg_dim: 4.0,
            card_blur: -3.0,
            card_alpha: f64::NAN,
        }
        .sanitized();
        assert_eq!(wild.wallpaper_source, "preset:matte");
        assert_eq!(
            (wild.bg_dim, wild.card_blur, wild.card_alpha),
            (0.9, 0.0, 0.72)
        );
        for ok in [
            "preset:crimson",
            "preset:cyberhex",
            "url:https://example.com/a.jpg",
            "file:wallpaper-01795110063198000000.webp",
        ] {
            assert!(is_valid_source(ok), "{ok}");
        }
        for bad in [
            "preset:neon",
            "url:javascript:alert(1)",
            "url:file:///etc/passwd",
            "file:wallpaper-1.exe",
            "file:wallpaper-1/../x.png",
            "",
        ] {
            assert!(!is_valid_source(bad), "{bad}");
        }
    }

    #[test]
    fn appearance_round_trips_and_keeps_other_keys() {
        let dir = temp_dir("settings");
        let path = dir.join("settings.json");
        assert_eq!(load_appearance(&path), Appearance::default());
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, br#"{"window":{"maximized":true}}"#).unwrap();
        let chosen = Appearance {
            wallpaper_source: "preset:cyberhex".to_string(),
            bg_dim: 0.4,
            card_blur: 20.0,
            card_alpha: 0.5,
        };
        store_appearance(&path, &chosen).unwrap();
        assert_eq!(load_appearance(&path), chosen);
        let root: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(root["window"]["maximized"], true);
        fs::write(&path, b"not json").unwrap();
        assert_eq!(load_appearance(&path), Appearance::default());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn images_are_identified_by_content() {
        assert_eq!(ImageKind::detect(&png()), Some(ImageKind::Png));
        assert_eq!(
            ImageKind::detect(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some(ImageKind::Jpeg)
        );
        assert_eq!(ImageKind::detect(b"GIF89a...."), Some(ImageKind::Gif));
        assert_eq!(
            ImageKind::detect(b"RIFF\x10\0\0\0WEBPVP8 "),
            Some(ImageKind::Webp)
        );
        assert_eq!(ImageKind::detect(b"MZ\x90\0 executable"), None);
        assert_eq!(
            ImageKind::from_url_path("/a/b/Photo.JPEG"),
            Some(ImageKind::Jpeg)
        );
        assert_eq!(ImageKind::from_url_path("/big.php"), None);
    }

    #[test]
    fn wallpapers_are_stored_served_and_pruned() {
        let dir = temp_dir("store");
        assert!(store_wallpaper(&dir, b"MZ not an image").is_err());
        let first = store_wallpaper(&dir, &png()).unwrap();
        assert!(is_wallpaper_name(&first) && first.ends_with(".png"));

        let served = wallpaper_response(Some(dir.clone()), &format!("/{first}"));
        assert_eq!(served.status(), StatusCode::OK);
        assert_eq!(served.headers()[header::CONTENT_TYPE], "image/png");
        assert_eq!(served.body(), &png());
        for bad in [
            "/../settings.json",
            "/wallpaper-1.png/../../x",
            "/missing.png",
        ] {
            let refused = wallpaper_response(Some(dir.clone()), bad);
            assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{bad}");
        }

        let mut names = vec![first];
        for _ in 0..KEEP_WALLPAPERS + 3 {
            names.push(store_wallpaper(&dir, &png()).unwrap());
        }
        let kept = fs::read_dir(&dir).unwrap().count();
        assert_eq!(kept, KEEP_WALLPAPERS);
        assert!(dir.join(names.last().unwrap()).is_file());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn page_share_images_are_found_and_resolved() {
        let base = Url::parse("https://wall.example.com/big.php?i=42").unwrap();
        let page = r#"<html><head>
            <META content="https://cdn.example.com/twitter.jpg" name="twitter:image">
            <meta property='og:image' content='/images/42.jpg?w=3840&amp;h=2160' />
            <meta property="og:title" content="A > B">
            </head></html>"#;
        assert_eq!(
            extract_meta_image(page, &base).as_deref(),
            Some("https://wall.example.com/images/42.jpg?w=3840&h=2160")
        );

        let twitter_only = r#"<meta name="twitter:image" content="https://cdn.example.com/t.png">"#;
        assert_eq!(
            extract_meta_image(twitter_only, &base).as_deref(),
            Some("https://cdn.example.com/t.png")
        );

        let secure_first = r#"<meta property="og:image" content="http://x.example/a.jpg">
            <meta property="og:image:secure_url" content="https://x.example/a.jpg">"#;
        assert_eq!(
            extract_meta_image(secure_first, &base).as_deref(),
            Some("https://x.example/a.jpg")
        );

        let link = r#"<link rel="image_src" href="//img.example.net/p.webp">"#;
        assert_eq!(
            extract_meta_image(link, &base).as_deref(),
            Some("https://img.example.net/p.webp")
        );

        let unsafe_scheme = r#"<meta property="og:image" content="javascript:alert(1)">"#;
        assert_eq!(extract_meta_image(unsafe_scheme, &base), None);
        assert_eq!(extract_meta_image("<metadata><p>no image</p>", &base), None);
        assert_eq!(
            extract_meta_image("<meta property=\"og:image\" content=\"x", &base),
            None
        );
    }

    #[test]
    fn attributes_parse_quoted_unquoted_and_bare() {
        let attrs = parse_attributes(r#" property="og:image" content=plain data-x='a b' async/"#);
        assert_eq!(
            attrs,
            vec![
                ("property".to_string(), "og:image".to_string()),
                ("content".to_string(), "plain".to_string()),
                ("data-x".to_string(), "a b".to_string()),
                ("async".to_string(), String::new()),
            ]
        );
        assert_eq!(decode_entities("a&amp;quot;b&quot;"), "a&quot;b\"");
    }

    #[test]
    fn direct_image_urls_resolve_without_a_request() {
        assert_eq!(
            resolve_image_url(" https://example.com/walls/neon.webp ").as_deref(),
            Ok("https://example.com/walls/neon.webp")
        );
        assert!(resolve_image_url("ftp://example.com/a.png").is_err());
        assert!(resolve_image_url("not a url").is_err());
    }
}
