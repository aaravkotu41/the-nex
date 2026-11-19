use crate::canary;
use crate::config::{self, AppConfig};
use crate::logger;
use crate::quarantine;
use std::env;
use std::ffi::{c_void, OsStr, OsString};
use std::fs;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use winrt_notification::{Duration as ToastDuration, Sound, Toast};

pub const SELF_EXE_NAME: &str = "the-nex.exe";
const SERVICE_DISPLAY_NAME: &str = "The Nex Endpoint Protection";
const SERVICE_DESCRIPTION: &str =
    "Real-time ransomware canary, zip bomb, malicious binary and living-off-the-land script protection.";
const RUN_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "TheNexNotifier";
const NOTIFIER_ARG: &str = "--notifier";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const CTRL_CLOSE_EVENT: u32 = 2;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
const ERROR_SERVICE_EXISTS: i32 = 1073;
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(20);

const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;
const WTD_REVOCATION_CHECK_NONE: u32 = 0x0000_0010;
const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;

const SID_SYSTEM: &str = "*S-1-5-18";
const SID_ADMINISTRATORS: &str = "*S-1-5-32-544";
const SID_USERS: &str = "*S-1-5-32-545";
const SID_EVERYONE: &str = "*S-1-1-0";

const SKIPPED_PROFILES: &[&str] = &[
    "public",
    "default",
    "default user",
    "all users",
    "defaultapppool",
    "wdagutilityaccount",
];

const PROTECTED_PROCESS_NAMES: &[&str] = &[
    "system",
    "system idle process",
    "idle",
    "registry",
    "memory compression",
    "secure system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    SELF_EXE_NAME,
];

/// Folders under otherwise admin-only trees that standard users can write to.
const USER_WRITABLE_FRAGMENTS: &[&str] = &[
    r"\temp\",
    r"\tmp\",
    r"\tasks\",
    r"\tracing\",
    r"\spool\",
    r"\com\dmp\",
    r"\fxstmp\",
    r"\registration\crmlog\",
    r"\catroot2\",
];

// FFI structs below are read by wintrust.dll, never by Rust.
#[allow(dead_code)]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const WINTRUST_ACTION_GENERIC_VERIFY_V2: Guid = Guid {
    data1: 0x00AA_C56B,
    data2: 0xCD44,
    data3: 0x11D0,
    data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

#[allow(dead_code)]
#[repr(C)]
struct WinTrustFileInfo {
    cb_struct: u32,
    file_path: *const u16,
    file_handle: *mut c_void,
    known_subject: *const Guid,
}

#[allow(dead_code)]
#[repr(C)]
struct WinTrustData {
    cb_struct: u32,
    policy_callback_data: *mut c_void,
    sip_client_data: *mut c_void,
    ui_choice: u32,
    revocation_checks: u32,
    union_choice: u32,
    file: *mut WinTrustFileInfo,
    state_action: u32,
    state_data: *mut c_void,
    url_reference: *const u16,
    prov_flags: u32,
    ui_context: u32,
    signature_settings: *mut c_void,
}

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn GetFileAttributesW(file_name: *const u16) -> u32;
    fn SetFileAttributesW(file_name: *const u16, attributes: u32) -> i32;
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
    fn GetConsoleProcessList(process_list: *mut u32, count: u32) -> u32;
    fn FreeConsole() -> i32;
}

#[link(name = "wintrust", kind = "raw-dylib")]
extern "system" {
    fn WinVerifyTrust(hwnd: *mut c_void, action_id: *mut Guid, data: *mut c_void) -> i32;
}

fn to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn system_root() -> PathBuf {
    env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

fn system32_tool(name: &str) -> PathBuf {
    system_root().join("System32").join(name)
}

fn users_root() -> PathBuf {
    let drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    PathBuf::from(format!(r"{drive}\Users"))
}

/// Case-insensitive, separator-normalized comparison key for Windows paths.
pub fn path_key(path: &Path) -> String {
    let mut key = path.to_string_lossy().replace('/', "\\").to_lowercase();
    if let Some(rest) = key.strip_prefix(r"\\?\unc\") {
        key = format!(r"\\{rest}");
    } else if let Some(rest) = key.strip_prefix(r"\\?\") {
        key = rest.to_string();
    }
    while key.len() > 3 && key.ends_with('\\') {
        key.pop();
    }
    key
}

pub fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = path_key(path);
    let root = path_key(root);
    if path == root {
        return true;
    }
    let prefix = if root.ends_with('\\') {
        root
    } else {
        format!("{root}\\")
    };
    path.starts_with(&prefix)
}

fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    paths
        .into_iter()
        .filter(|p| seen.insert(path_key(p)))
        .collect()
}

/// Real interactive profiles under %SystemDrive%\Users (junctions and built-ins skipped).
fn user_profiles() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(users_root()) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            let Ok(kind) = entry.file_type() else {
                return false;
            };
            let name = entry.file_name().to_string_lossy().to_lowercase();
            kind.is_dir()
                && !kind.is_symlink()
                && !name.starts_with('.')
                && !SKIPPED_PROFILES.contains(&name.as_str())
        })
        .map(|entry| entry.path())
        .collect()
}

/// `names` inside the profile plus inside any OneDrive* folder (known-folder redirection).
fn profile_folders(profile: &Path, names: &[&str]) -> Vec<PathBuf> {
    let mut roots = vec![profile.to_path_buf()];
    if let Ok(entries) = fs::read_dir(profile) {
        roots.extend(
            entries
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .to_lowercase()
                        .starts_with("onedrive")
                        && e.path().is_dir()
                })
                .map(|e| e.path()),
        );
    }
    roots
        .iter()
        .flat_map(|root| names.iter().map(move |name| root.join(name)))
        .filter(|p| p.is_dir())
        .collect()
}

pub fn discover_watched_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for profile in user_profiles() {
        dirs.extend(profile_folders(&profile, &["Downloads", "Desktop"]));
        let user_temp = profile.join("AppData").join("Local").join("Temp");
        if user_temp.is_dir() {
            dirs.push(user_temp);
        }
    }
    for temp in [system_root().join("Temp"), env::temp_dir()] {
        if temp.is_dir() {
            dirs.push(temp);
        }
    }
    dedup_paths(dirs)
}

pub fn discover_canary_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for profile in user_profiles() {
        dirs.extend(profile_folders(&profile, &["Desktop", "Documents"]));
    }
    dedup_paths(dirs)
}

pub fn set_hidden_file(path: &Path) {
    let wide = to_wide(path.as_os_str());
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives both calls.
    unsafe {
        let attributes = GetFileAttributesW(wide.as_ptr());
        if attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_HIDDEN == 0 {
            SetFileAttributesW(wide.as_ptr(), attributes | FILE_ATTRIBUTE_HIDDEN);
        }
    }
}

fn run_tool<I, S>(program: &Path, args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let mut message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if message.is_empty() {
        message = String::from_utf8_lossy(&output.stdout).trim().to_string();
    }
    Err(format!(
        "{} failed ({}): {message}",
        program.display(),
        output.status
    ))
}

fn icacls(path: &Path, args: &[&str]) -> bool {
    let mut full: Vec<&OsStr> = vec![path.as_os_str()];
    full.extend(args.iter().map(OsStr::new));
    run_tool(&system32_tool("icacls.exe"), full).is_ok()
}

/// Read-only, owned by Administrators, readable only by SYSTEM/Administrators, execute denied to everyone.
pub fn lock_quarantined_file(path: &Path) {
    let _ = quarantine::set_readonly(path, true);
    icacls(path, &["/setowner", SID_ADMINISTRATORS]);
    let system = format!("{SID_SYSTEM}:(F)");
    let admins = format!("{SID_ADMINISTRATORS}:(F)");
    if !icacls(
        path,
        &[
            "/inheritance:r",
            "/grant:r",
            system.as_str(),
            admins.as_str(),
        ],
    ) {
        logger::warn(format!("could not restrict ACL on {}", path.display()));
    }
    let deny_execute = format!("{SID_EVERYONE}:(X)");
    icacls(path, &["/deny", deny_execute.as_str()]);
}

pub fn unlock_restored_file(path: &Path) {
    icacls(path, &["/reset"]);
    let _ = quarantine::set_readonly(path, false);
}

pub fn send_desktop_notification(title: &str, body: &str) {
    let toast = Toast::new(Toast::POWERSHELL_APP_ID)
        .title(title)
        .text1(body)
        .sound(Some(Sound::SMS))
        .duration(ToastDuration::Short);
    if let Err(primary) = toast.show() {
        let fallback = notify_rust::Notification::new()
            .summary(title)
            .body(body)
            .show()
            .map(|_| ());
        if let Err(secondary) = fallback {
            logger::warn(format!(
                "desktop notification failed (winrt: {primary:?}; notify-rust: {secondary})"
            ));
        }
    }
}

pub fn is_protected_process(pid: u32, name: &str) -> bool {
    if pid == 0 || pid == 4 || pid == std::process::id() {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    PROTECTED_PROCESS_NAMES.contains(&lower.as_str())
}

fn trusted_roots() -> &'static [String] {
    static ROOTS: OnceLock<Vec<String>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let root = system_root();
        let mut dirs = vec![
            root.join("System32"),
            root.join("SysWOW64"),
            root.join("WinSxS"),
            root.join("SystemApps"),
            root.join("ImmersiveControlPanel"),
            root.join("Microsoft.NET"),
        ];
        for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(dir) = env::var_os(var) {
                dirs.push(PathBuf::from(dir));
            }
        }
        let mut keys: Vec<String> = dirs.iter().map(|d| path_key(d)).collect();
        keys.sort();
        keys.dedup();
        keys
    })
}

fn is_in_trusted_root(path: &Path) -> bool {
    let key = path_key(path);
    if USER_WRITABLE_FRAGMENTS.iter().any(|f| key.contains(f)) {
        return false;
    }
    trusted_roots()
        .iter()
        .any(|root| key.starts_with(&format!("{root}\\")))
}

fn has_valid_authenticode(path: &Path) -> bool {
    let wide = to_wide(path.as_os_str());
    let mut file_info = WinTrustFileInfo {
        cb_struct: size_of::<WinTrustFileInfo>() as u32,
        file_path: wide.as_ptr(),
        file_handle: ptr::null_mut(),
        known_subject: ptr::null(),
    };
    let mut data = WinTrustData {
        cb_struct: size_of::<WinTrustData>() as u32,
        policy_callback_data: ptr::null_mut(),
        sip_client_data: ptr::null_mut(),
        ui_choice: WTD_UI_NONE,
        revocation_checks: WTD_REVOKE_NONE,
        union_choice: WTD_CHOICE_FILE,
        file: &mut file_info,
        state_action: WTD_STATEACTION_VERIFY,
        state_data: ptr::null_mut(),
        url_reference: ptr::null(),
        prov_flags: WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ui_context: 0,
        signature_settings: ptr::null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let no_ui = usize::MAX as *mut c_void;
    // SAFETY: all pointers reference live, correctly laid out structures for the call;
    // the CLOSE call releases the state allocated by VERIFY.
    unsafe {
        let status = WinVerifyTrust(no_ui, &mut action, (&mut data as *mut WinTrustData).cast());
        data.state_action = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(no_ui, &mut action, (&mut data as *mut WinTrustData).cast());
        status == 0
    }
}

/// Admin-only system/program folders, or a valid embedded Authenticode signature.
pub fn is_trusted_binary(path: &Path) -> bool {
    is_in_trusted_root(path) || has_valid_authenticode(path)
}

fn win32_code(err: &windows_service::Error) -> Option<i32> {
    match err {
        windows_service::Error::Winapi(io) => io.raw_os_error(),
        _ => None,
    }
}

fn service_error(context: &str, err: windows_service::Error) -> String {
    match win32_code(&err) {
        Some(5) => format!("{context}: access denied (run from an elevated Administrator prompt)"),
        Some(code) => format!("{context}: {err} (Win32 error {code})"),
        None => format!("{context}: {err}"),
    }
}

fn service_info(executable: PathBuf) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(config::SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: Vec::new(),
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    }
}

fn restart_action(delay_secs: u64) -> ServiceAction {
    ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(delay_secs),
    }
}

fn harden_data_dirs(cfg: &AppConfig) -> Vec<String> {
    let mut notes = Vec::new();
    if let Err(e) = cfg.ensure_dirs() {
        notes.push(e);
    }
    let system = format!("{SID_SYSTEM}:(OI)(CI)F");
    let admins = format!("{SID_ADMINISTRATORS}:(OI)(CI)F");
    let users = format!("{SID_USERS}:(OI)(CI)RX");
    let base_grants = [
        "/inheritance:r",
        "/grant:r",
        system.as_str(),
        admins.as_str(),
        users.as_str(),
    ];
    if !icacls(&cfg.base_dir, &base_grants) {
        notes.push(format!(
            "could not restrict ACL on {}",
            cfg.base_dir.display()
        ));
    }
    if !icacls(
        &cfg.quarantine_dir,
        &[
            "/inheritance:r",
            "/grant:r",
            system.as_str(),
            admins.as_str(),
        ],
    ) {
        notes.push(format!(
            "could not restrict ACL on {}",
            cfg.quarantine_dir.display()
        ));
    }
    notes
}

fn register_notifier_autostart(exe: &Path) -> Result<(), String> {
    let command = format!("\"{}\" {NOTIFIER_ARG}", exe.display());
    run_tool(
        &system32_tool("reg.exe"),
        [
            "add",
            RUN_KEY,
            "/v",
            RUN_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            command.as_str(),
            "/f",
        ],
    )
}

fn unregister_notifier_autostart() -> bool {
    run_tool(
        &system32_tool("reg.exe"),
        ["delete", RUN_KEY, "/v", RUN_VALUE, "/f"],
    )
    .is_ok()
}

fn stop_notifier_processes() -> usize {
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    let me = std::process::id();
    sys.processes()
        .values()
        .filter(|p| {
            p.pid().as_u32() != me
                && OsStr::new(p.name())
                    .to_string_lossy()
                    .eq_ignore_ascii_case(SELF_EXE_NAME)
                && p.cmd().iter().any(|arg| {
                    OsStr::new(arg)
                        .to_string_lossy()
                        .eq_ignore_ascii_case(NOTIFIER_ARG)
                })
        })
        .filter(|p| p.kill())
        .count()
}

pub fn install_service() -> Result<String, String> {
    let exe = env::current_exe().map_err(|e| format!("cannot resolve executable path: {e}"))?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| service_error("cannot open the Service Control Manager", e))?;

    let info = service_info(exe.clone());
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START;
    let mut notes = Vec::new();
    let service = match manager.create_service(&info, access) {
        Ok(service) => {
            notes.push(format!("service '{}' registered", config::SERVICE_NAME));
            service
        }
        Err(e) if win32_code(&e) == Some(ERROR_SERVICE_EXISTS) => {
            let service = manager
                .open_service(config::SERVICE_NAME, access)
                .map_err(|e| service_error("cannot open existing service", e))?;
            service
                .change_config(&info)
                .map_err(|e| service_error("cannot update existing service", e))?;
            notes.push(format!("service '{}' updated", config::SERVICE_NAME));
            service
        }
        Err(e) => return Err(service_error("cannot create service", e)),
    };

    service
        .set_description(SERVICE_DESCRIPTION)
        .map_err(|e| service_error("cannot set service description", e))?;
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                restart_action(5),
                restart_action(5),
                restart_action(30),
            ]),
        })
        .map_err(|e| service_error("cannot set restart-on-failure policy", e))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| service_error("cannot enable failure actions", e))?;

    notes.extend(harden_data_dirs(&AppConfig::for_base_dir(
        &config::default_base_dir(),
    )));
    match register_notifier_autostart(&exe) {
        Ok(()) => notes.push(format!(
            "notifier autostart registered ({RUN_KEY}\\{RUN_VALUE})"
        )),
        Err(e) => {
            return Err(format!(
                "service installed but notifier autostart failed: {e}"
            ))
        }
    }
    notes.push(format!("executable: {}", exe.display()));
    Ok(notes.join("\n"))
}

pub fn uninstall_service() -> Result<String, String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| service_error("cannot open the Service Control Manager", e))?;
    let mut notes = Vec::new();
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    match manager.open_service(config::SERVICE_NAME, access) {
        Ok(service) => {
            if let Ok(status) = service.query_status() {
                if status.current_state != ServiceState::Stopped {
                    let _ = service.stop();
                    let started = Instant::now();
                    while started.elapsed() < SERVICE_STOP_TIMEOUT {
                        match service.query_status() {
                            Ok(s) if s.current_state == ServiceState::Stopped => break,
                            Ok(_) => thread::sleep(Duration::from_millis(250)),
                            Err(_) => break,
                        }
                    }
                }
            }
            service
                .delete()
                .map_err(|e| service_error("cannot delete service", e))?;
            notes.push(format!("service '{}' removed", config::SERVICE_NAME));
        }
        Err(e) if win32_code(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
            notes.push(format!(
                "service '{}' was not installed",
                config::SERVICE_NAME
            ));
        }
        Err(e) => return Err(service_error("cannot open service", e)),
    }

    if unregister_notifier_autostart() {
        notes.push("notifier autostart removed".to_string());
    }
    let stopped = stop_notifier_processes();
    if stopped > 0 {
        notes.push(format!("stopped {stopped} notifier process(es)"));
    }
    let removed = canary::remove_canaries(&discover_canary_dirs());
    notes.push(format!("removed {removed} canary file(s)"));
    Ok(notes.join("\n"))
}

static SERVICE_CONTEXT: OnceLock<(Arc<AtomicBool>, AppConfig)> = OnceLock::new();

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = service_body() {
        logger::error(format!("service terminated with error: {e}"));
    }
}

fn service_body() -> windows_service::Result<()> {
    let Some((shutdown, cfg)) = SERVICE_CONTEXT.get().cloned() else {
        return Ok(());
    };
    let stop_flag = Arc::clone(&shutdown);
    let handler = move |control: ServiceControl| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                stop_flag.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status = service_control_handler::register(config::SERVICE_NAME, handler)?;
    status.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ))?;
    crate::engine::run(cfg, shutdown);
    status.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
    ))?;
    Ok(())
}

/// Hands control to the SCM dispatcher; returns when the service stops.
pub fn run_service(shutdown: Arc<AtomicBool>, cfg: AppConfig) -> Result<(), String> {
    if SERVICE_CONTEXT.set((shutdown, cfg)).is_err() {
        return Err("service context already initialized".to_string());
    }
    service_dispatcher::start(config::SERVICE_NAME, ffi_service_main).map_err(|e| {
        if win32_code(&e) == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            "not launched by the Service Control Manager; use --console to run interactively or --install to register the service".to_string()
        } else {
            format!("service dispatcher failed: {e}")
        }
    })
}

static CONSOLE_SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> i32 {
    if let Some(flag) = CONSOLE_SHUTDOWN.get() {
        flag.store(true, Ordering::SeqCst);
    }
    if ctrl_type == CTRL_CLOSE_EVENT {
        // Window close terminates the process when the handler returns; give workers a moment.
        thread::sleep(Duration::from_secs(2));
    }
    1
}

pub fn install_ctrlc_handler(shutdown: Arc<AtomicBool>) {
    let _ = CONSOLE_SHUTDOWN.set(shutdown);
    // SAFETY: registers a 'static handler function with the matching signature.
    unsafe {
        SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
    }
}

/// Closes the console window when this process owns it (Run-key launch of a console binary).
pub fn detach_console() {
    let mut pids = [0u32; 4];
    // SAFETY: the buffer length passed matches the array.
    unsafe {
        if GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) == 1 {
            FreeConsole();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_processes() {
        assert!(is_protected_process(0, "anything"));
        assert!(is_protected_process(4, "System"));
        assert!(is_protected_process(std::process::id(), "whatever.exe"));
        assert!(is_protected_process(1234, "Explorer.EXE"));
        assert!(is_protected_process(1234, "lsass.exe"));
        assert!(is_protected_process(1234, "The-Nex.exe"));
        assert!(!is_protected_process(1234, "malware.exe"));
    }

    #[test]
    fn path_keys_normalize() {
        assert_eq!(path_key(Path::new(r"C:\Users\A\")), r"c:\users\a");
        assert_eq!(path_key(Path::new(r"\\?\C:\Users\A")), r"c:\users\a");
        assert_eq!(path_key(Path::new("C:/Users/A")), r"c:\users\a");
        assert!(path_is_within(
            Path::new(r"C:\Users\A\Desktop\x"),
            Path::new(r"c:\users\a")
        ));
        assert!(!path_is_within(
            Path::new(r"C:\Users\Ab\x"),
            Path::new(r"C:\Users\A")
        ));
    }

    #[test]
    fn system_binaries_are_trusted_and_temp_is_not() {
        assert!(is_trusted_binary(&system32_tool("notepad.exe")));
        assert!(!is_in_trusted_root(
            &system_root().join("Temp").join("x.exe")
        ));
        assert!(!is_in_trusted_root(
            &system32_tool("spool")
                .join("drivers")
                .join("color")
                .join("x.exe")
        ));
    }

    #[test]
    fn unsigned_temp_file_is_not_trusted() {
        let path = env::temp_dir().join(format!("thenex-untrusted-{}.exe", std::process::id()));
        fs::write(&path, b"MZ not really a binary").unwrap();
        assert!(!is_trusted_binary(&path));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn hidden_attribute_is_applied() {
        let path = env::temp_dir().join(format!("thenex-hidden-{}.txt", std::process::id()));
        fs::write(&path, b"x").unwrap();
        set_hidden_file(&path);
        let wide = to_wide(path.as_os_str());
        // SAFETY: valid NUL-terminated path.
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        assert_ne!(attributes, INVALID_FILE_ATTRIBUTES);
        assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN, 0);
        let _ = fs::remove_file(&path);
    }
}
