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
        config::set_operator_sid(&sid).context("persist Windows operator SID")?;
    }
    Ok(())
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
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })
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
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1063) => {
            Ok(false)
        }
        Err(error) => Err(anyhow::anyhow!(error)),
    }
}
