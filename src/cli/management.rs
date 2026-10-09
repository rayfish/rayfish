//! Managed-machine enrollment, inventory, and delegated network operations.

use std::fmt::{self, Display, Formatter};
use std::time::Duration;

use crate::*;

#[derive(serde::Serialize)]
#[serde(transparent)]
struct ManagedMachinesOutput<'a>(&'a [ipc::ManagedMachineInfo]);

impl Display for ManagedMachinesOutput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return writeln!(f, "no enrolled machines");
        }
        let rows = self
            .0
            .iter()
            .map(|machine| {
                let short_id = machine.identity.fmt_short().to_string();
                let networks = machine
                    .networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let state = <&str>::from(machine.state);
                vec![
                    layout::Cell::new(
                        machine.hostname.to_string(),
                        style::value(machine.hostname.as_ref()),
                    ),
                    layout::Cell::new(short_id.clone(), style::rose(&short_id)),
                    layout::Cell::new(state, style::faint(state)),
                    layout::Cell::new(networks.clone(), style::faint(&networks)),
                ]
            })
            .collect();
        write!(
            f,
            "{}",
            table(&["machine", "id", "state", "networks"], rows, 2)
        )
    }
}

#[derive(serde::Serialize)]
struct MachineEnrollmentCreatedOutput<'a> {
    id: &'a ipc::EnrollmentCredentialId,
    ticket: &'a ipc::EnrollmentTicket,
    expires_at: ipc::UnixTimestampSecs,
    reusable: bool,
}

impl Display for MachineEnrollmentCreatedOutput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "enrollment {}", self.id)?;
        writeln!(f, "{}", self.ticket)?;
        writeln!(
            f,
            "run on the managed machine: ray up --controller {}",
            self.ticket
        )
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct MachineEnrollmentsOutput<'a>(&'a [ipc::MachineEnrollmentInfo]);

impl Display for MachineEnrollmentsOutput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for enrollment in self.0 {
            let kind = if enrollment.reusable {
                "reusable"
            } else {
                "one-time"
            };
            let status = <&str>::from(enrollment.status);
            writeln!(
                f,
                "{}  {}  {}  uses {}",
                enrollment.id, kind, status, enrollment.uses
            )?;
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct ControllersOutput<'a>(&'a [ipc::ControllerInfo]);

impl Display for ControllersOutput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return writeln!(f, "no authorized controllers");
        }
        for controller in self.0 {
            writeln!(
                f,
                "{}  {}",
                controller.identity.fmt_short(),
                controller.identity
            )?;
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct ManagementMessageOutput<'a> {
    message: &'a str,
}

impl Display for ManagementMessageOutput<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.message)
    }
}

pub(crate) async fn ipc_machines(action: Option<MachinesAction>) -> Result<()> {
    let request = match action {
        None => ipc::IpcMessage::ManagedMachines { probe: true },
        Some(MachinesAction::Enroll { reusable, expires }) => {
            let expires_in = enrollment_ttl(reusable, expires.as_deref())?;
            ipc::IpcMessage::MachineEnrollmentCreate {
                expires_in,
                reusable,
            }
        }
        Some(MachinesAction::Enrollments) => ipc::IpcMessage::MachineEnrollmentList,
        Some(MachinesAction::RevokeEnrollment { credential }) => {
            ipc::IpcMessage::MachineEnrollmentRevoke { credential }
        }
        Some(MachinesAction::Forget { machine }) => {
            ipc::IpcMessage::ManagedMachineForget { machine }
        }
        Some(MachinesAction::Confirm { machine }) => {
            ipc::IpcMessage::ManagedMachineConfirm { machine }
        }
    };
    let response = ipc_request(request).await?;
    match response {
        ipc::IpcMessage::ManagedMachinesResponse { machines } => {
            printout(&ManagedMachinesOutput(&machines))?;
        }
        ipc::IpcMessage::MachineEnrollmentCreated {
            id,
            ticket,
            expires_at,
            reusable,
        } => {
            printout(&MachineEnrollmentCreatedOutput {
                id: &id,
                ticket: &ticket,
                expires_at,
                reusable,
            })?;
        }
        ipc::IpcMessage::MachineEnrollments { enrollments } => {
            printout(&MachineEnrollmentsOutput(&enrollments))?;
        }
        ipc::IpcMessage::Ok { message } => print_management_message(&message)?,
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

pub(crate) async fn ipc_controller(action: Option<ControllerAction>) -> Result<()> {
    match action.unwrap_or(ControllerAction::List) {
        ControllerAction::Add { ticket } => ipc_enroll_controller(&ticket).await,
        ControllerAction::List => {
            let response = ipc_request(ipc::IpcMessage::ControllerList).await?;
            match response {
                ipc::IpcMessage::Controllers { controllers } => {
                    printout(&ControllersOutput(&controllers))?;
                }
                ipc::IpcMessage::Error { message } => fail_with("error", &message),
                other => fail_unexpected(&other),
            }
            Ok(())
        }
        ControllerAction::Revoke { identity, all } => {
            if !all && identity.is_none() {
                anyhow::bail!("controller identity is required, or pass --all");
            }
            let response = ipc_request(ipc::IpcMessage::ControllerRevoke {
                identity: if all { None } else { identity },
            })
            .await?;
            print_simple_response(response)
        }
    }
}

pub(crate) async fn ipc_enroll_controller(ticket: &ipc::EnrollmentTicket) -> Result<()> {
    let response = ipc_request(ipc::IpcMessage::EnrollController {
        ticket: ticket.clone(),
    })
    .await?;
    print_simple_response(response)
}

pub(crate) async fn ipc_delegated_join(
    machine: &ipc::ManagedMachineSelector,
    network: &ipc::NetworkName,
    hostname: Option<ipc::MachineHostname>,
    auto_accept_firewall: bool,
    auto_accept_files: bool,
) -> Result<()> {
    let message = ipc_delegated_join_request(
        machine,
        network,
        hostname,
        auto_accept_firewall,
        auto_accept_files,
    )
    .await?;
    println!("{message}");
    Ok(())
}

pub(crate) async fn ipc_delegated_join_request(
    machine: &ipc::ManagedMachineSelector,
    network: &ipc::NetworkName,
    hostname: Option<ipc::MachineHostname>,
    auto_accept_firewall: bool,
    auto_accept_files: bool,
) -> Result<String> {
    let response = ipc_request(ipc::IpcMessage::DelegatedJoin {
        machine: machine.clone(),
        network: network.clone(),
        hostname,
        auto_accept_firewall,
        auto_accept_files,
    })
    .await?;
    result_message(response)
}

pub(crate) async fn ipc_delegated_leave(
    machine: &ipc::ManagedMachineSelector,
    network: &ipc::NetworkName,
) -> Result<()> {
    let message = ipc_delegated_leave_request(machine, network).await?;
    println!("{message}");
    Ok(())
}

pub(crate) async fn ipc_delegated_leave_request(
    machine: &ipc::ManagedMachineSelector,
    network: &ipc::NetworkName,
) -> Result<String> {
    let response = ipc_request(ipc::IpcMessage::DelegatedLeave {
        machine: machine.clone(),
        network: network.clone(),
    })
    .await?;
    result_message(response)
}

pub(crate) async fn ipc_request(request: ipc::IpcMessage) -> Result<ipc::IpcMessage> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, request).await?;
    ipc::recv(&mut stream).await
}

pub(crate) async fn ipc_management_overview(
    show_machines: bool,
) -> (Vec<ipc::ControllerInfo>, Vec<ipc::ManagedMachineInfo>) {
    let controllers = async {
        match ipc_request(ipc::IpcMessage::ControllerList).await {
            Ok(ipc::IpcMessage::Controllers { controllers }) => controllers,
            _ => Vec::new(),
        }
    };
    let machines = async {
        if !show_machines {
            return Vec::new();
        }
        match ipc_request(ipc::IpcMessage::ManagedMachines { probe: true }).await {
            Ok(ipc::IpcMessage::ManagedMachinesResponse { machines }) => machines,
            _ => Vec::new(),
        }
    };
    tokio::join!(controllers, machines)
}

fn print_simple_response(response: ipc::IpcMessage) -> Result<()> {
    match response {
        ipc::IpcMessage::Ok { message } => print_management_message(&message)?,
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

fn print_management_message(message: &str) -> Result<()> {
    printout(&ManagementMessageOutput { message })
}

fn enrollment_ttl(reusable: bool, expires: Option<&str>) -> Result<Duration> {
    let default = if reusable { "30d" } else { "7d" };
    let expires_secs = parse_duration_secs(expires.unwrap_or(default))?;
    anyhow::ensure!(
        expires_secs > 0,
        "enrollment expiration must be greater than zero"
    );
    Ok(Duration::from_secs(expires_secs))
}

fn result_message(response: ipc::IpcMessage) -> Result<String> {
    match response {
        ipc::IpcMessage::Ok { message } => Ok(message),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!(unexpected_detail(&other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_ttl_rejects_zero() {
        let error = enrollment_ttl(false, Some("0s")).unwrap_err();
        assert_eq!(
            error.to_string(),
            "enrollment expiration must be greater than zero"
        );
    }

    #[test]
    fn enrollment_ttl_uses_kind_specific_default() {
        assert_eq!(
            enrollment_ttl(false, None).unwrap(),
            Duration::from_secs(7 * 24 * 60 * 60)
        );
        assert_eq!(
            enrollment_ttl(true, None).unwrap(),
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }
}
