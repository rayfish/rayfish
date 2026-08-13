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
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
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
    let service = match scm.open_service(SERVICE_NAME, ServiceAccess::ALL_ACCESS) {
        Ok(service) => {
            if service.query_status()?.current_state != ServiceState::Stopped {
                let _ = service.stop();
                wait_for_state(&service, ServiceState::Stopped)?;
            }
            service
                .change_config(&info)
                .context("refresh rayfish service")?;
            service
        }
        Err(_) => scm
            .create_service(&info, ServiceAccess::ALL_ACCESS)
            .context("create rayfish Windows service")?,
    };
    configure_failure_actions(&service)?;
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
    match start_transition(service.query_status()?.current_state) {
        StartTransition::AlreadyRunning => return Ok(()),
        StartTransition::WaitForRunning => return wait_for_state(&service, ServiceState::Running),
        StartTransition::WaitForStoppedThenStart => {
            wait_for_state(&service, ServiceState::Stopped)?;
        }
        StartTransition::StartNow => {}
        StartTransition::RejectPaused => {
            anyhow::bail!("cannot start rayfish Windows service while it is paused")
        }
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
    status_with_exit_code(handle, state, ServiceExitCode::NO_ERROR)
}

fn status_with_exit_code(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    exit_code: ServiceExitCode,
) -> windows_service::Result<()> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: controls_accepted(state),
        exit_code,
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
    match result {
        Ok(()) => status(&handle, ServiceState::Stopped),
        Err(error) => {
            status_with_exit_code(&handle, ServiceState::Stopped, ServiceExitCode::Win32(1))?;
            Err(windows_service::Error::Winapi(std::io::Error::other(
                error.to_string(),
            )))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartTransition {
    AlreadyRunning,
    WaitForRunning,
    WaitForStoppedThenStart,
    StartNow,
    RejectPaused,
}

fn start_transition(state: ServiceState) -> StartTransition {
    match state {
        ServiceState::Running => StartTransition::AlreadyRunning,
        ServiceState::StartPending | ServiceState::ContinuePending => {
            StartTransition::WaitForRunning
        }
        ServiceState::StopPending => StartTransition::WaitForStoppedThenStart,
        ServiceState::Stopped => StartTransition::StartNow,
        ServiceState::PausePending | ServiceState::Paused => StartTransition::RejectPaused,
    }
}

fn failure_actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(60),
            },
        ]),
    }
}

fn configure_failure_actions(service: &windows_service::service::Service) -> Result<()> {
    service
        .update_failure_actions(failure_actions())
        .context("configure Windows service failure actions")?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .context("enable restart for non-crash Windows service failures")?;
    Ok(())
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
        SERVICE_NAME, ServiceActionType, ServiceStartType, ServiceState, StartTransition,
        controls_accepted, failure_actions, is_console_dispatch_error, service_info,
        start_transition,
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
    fn start_transition_waits_for_the_state_that_can_actually_arrive() {
        assert_eq!(
            start_transition(ServiceState::StartPending),
            StartTransition::WaitForRunning
        );
        assert_eq!(
            start_transition(ServiceState::ContinuePending),
            StartTransition::WaitForRunning
        );
        assert_eq!(
            start_transition(ServiceState::StopPending),
            StartTransition::WaitForStoppedThenStart
        );
        assert_eq!(
            start_transition(ServiceState::Stopped),
            StartTransition::StartNow
        );
        assert_eq!(
            start_transition(ServiceState::Paused),
            StartTransition::RejectPaused
        );
    }

    #[test]
    fn failure_policy_restarts_three_times_and_resets_daily() {
        let policy = failure_actions();
        assert!(matches!(
            policy.reset_period,
            windows_service::service::ServiceFailureResetPeriod::After(duration)
                if duration == std::time::Duration::from_secs(24 * 60 * 60)
        ));
        let actions = policy.actions.unwrap();
        assert_eq!(actions.len(), 3);
        assert!(
            actions
                .iter()
                .all(|action| action.action_type == ServiceActionType::Restart)
        );
    }

    #[test]
    fn console_dispatch_error_is_classified_without_touching_scm() {
        let console = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(1063));
        let denied = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));
        assert!(is_console_dispatch_error(&console));
        assert!(!is_console_dispatch_error(&denied));
    }
}
