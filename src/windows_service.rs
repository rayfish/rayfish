#![cfg(windows)]

//! Windows SCM integration. The installed service runs the same `daemon`
//! command as the console binary, under LocalSystem.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::{config, daemon, stats};

pub(crate) const SERVICE_NAME: &str = "rayfish";

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&OsStr>, access)
        .context("open Windows Service Control Manager")
}

fn service_info(executable: &Path) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("Rayfish Mesh VPN"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: PathBuf::from(executable),
        launch_arguments: vec![OsString::from("daemon")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    }
}

fn wait_for_state(
    service: &windows_service::service::Service,
    desired: ServiceState,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = service.query_status()?.current_state;
        if state == desired {
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "timed out waiting for service state {desired:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub fn install(executable: &Path) -> Result<()> {
    let info = service_info(executable);
    let scm = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    match scm.open_service(SERVICE_NAME, ServiceAccess::ALL_ACCESS) {
        Ok(service) => {
            if service.query_status()?.current_state != ServiceState::Stopped {
                let _ = service.stop();
                wait_for_state(&service, ServiceState::Stopped)?;
            }
            service
                .change_config(&info)
                .context("refresh rayfish service")?;
        }
        Err(_) => scm
            .create_service(&info, ServiceAccess::ALL_ACCESS)
            .context("create rayfish Windows service")
            .map(|_| ())?,
    }
    if let Some(sid) = crate::windows_identity::current_user_sid() {
        config::claim_operator_sid(&sid).context("claim Windows operator SID")?;
    }
    Ok(())
}

pub fn set_operator_account(account: &OsStr) -> Result<String> {
    anyhow::ensure!(
        crate::windows_identity::is_current_process_elevated_admin(),
        "setting the Windows operator requires an elevated Administrator terminal"
    );
    let sid = crate::windows_identity::account_sid(account)?;
    let previous = config::operator_sid()?;
    let was_running = open(ServiceAccess::QUERY_STATUS)?
        .query_status()?
        .current_state
        == ServiceState::Running;
    if was_running {
        stop()?;
    }
    if let Err(error) = config::set_operator_sid(&sid) {
        if was_running {
            let _ = start();
        }
        return Err(error);
    }
    if was_running && let Err(error) = start() {
        let _ = config::replace_operator_sid_if_matches(&sid, previous.as_deref());
        let _ = start();
        return Err(error).context("restart service after setting Windows operator");
    }
    Ok(sid)
}

fn open(access: ServiceAccess) -> Result<windows_service::service::Service> {
    manager(ServiceManagerAccess::CONNECT)?
        .open_service(SERVICE_NAME, access)
        .context("open rayfish Windows service")
}

pub fn exists() -> bool {
    open(ServiceAccess::QUERY_STATUS).is_ok()
}

pub fn start() -> Result<()> {
    let service = open(ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state == ServiceState::Running {
        return Ok(());
    }
    if service.query_status()?.current_state != ServiceState::Stopped {
        wait_for_state(&service, ServiceState::Stopped)?;
    }
    service
        .start::<OsString>(&[])
        .context("start rayfish Windows service")?;
    wait_for_state(&service, ServiceState::Running)
}

pub fn stop() -> Result<()> {
    let service = open(ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop().context("stop rayfish Windows service")?;
        wait_for_state(&service, ServiceState::Stopped)?;
    }
    Ok(())
}

pub fn remove() -> Result<()> {
    let service = open(ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop().context("stop rayfish Windows service")?;
        wait_for_state(&service, ServiceState::Stopped)?;
    }
    service.delete().context("remove rayfish Windows service")
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(%error, "rayfish Windows service exited with an error");
    }
}

fn status(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
) -> windows_service::Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls_accepted(state),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })
}

fn controls_accepted(state: ServiceState) -> ServiceControlAccept {
    if state == ServiceState::Running {
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
    } else {
        ServiceControlAccept::empty()
    }
}

fn run_service() -> windows_service::Result<()> {
    let token = CancellationToken::new();
    let stop_token = token.clone();
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            stop_token.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(SERVICE_NAME, handler)?;
    status(&handle, ServiceState::Running)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| windows_service::Error::Winapi(std::io::Error::other(error)))?;
    let result = runtime.block_on(async move {
        let metrics = std::sync::Arc::new(stats::ForwardMetrics::default());
        metrics.spawn_logger(token.clone());
        daemon::run_daemon(token, metrics).await
    });
    status(&handle, ServiceState::Stopped)?;
    result.map_err(|error| windows_service::Error::Winapi(std::io::Error::other(error.to_string())))
}

/// Start the SCM dispatcher. A normal console invocation returns `Ok(false)`
/// with Win32 error 1063 and continues through the regular async main path.
pub fn run_if_service() -> Result<bool> {
    match windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        Err(error) if is_console_dispatch_error(&error) => Ok(false),
        Err(error) => Err(anyhow::anyhow!(error)),
    }
}

fn is_console_dispatch_error(error: &windows_service::Error) -> bool {
    matches!(error, windows_service::Error::Winapi(error) if error.raw_os_error() == Some(1063))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        SERVICE_NAME, ServiceStartType, ServiceState, controls_accepted, is_console_dispatch_error,
        service_info,
    };
    use windows_service::service::{ServiceControlAccept, ServiceType};

    #[test]
    fn service_info_is_auto_starting_local_system_compatible_daemon() {
        let info = service_info(Path::new(r"C:\Program Files\Rayfish\ray.exe"));
        assert_eq!(info.name.to_string_lossy(), SERVICE_NAME);
        assert_eq!(info.display_name.to_string_lossy(), "Rayfish Mesh VPN");
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert_eq!(
            info.launch_arguments,
            vec![std::ffi::OsString::from("daemon")]
        );
        assert!(info.dependencies.is_empty());
        assert!(info.account_name.is_none());
        assert!(info.account_password.is_none());
    }

    #[test]
    fn service_controls_are_fail_closed_outside_running_state() {
        assert_eq!(
            controls_accepted(ServiceState::Running),
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        );
        assert!(controls_accepted(ServiceState::Stopped).is_empty());
        assert!(controls_accepted(ServiceState::StartPending).is_empty());
    }

    #[test]
    fn console_dispatch_error_is_classified_without_touching_scm() {
        let console = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(1063));
        let denied = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));
        assert!(is_console_dispatch_error(&console));
        assert!(!is_console_dispatch_error(&denied));
    }
}
