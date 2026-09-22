//! Managed-machine enrollment, inventory, and delegated network operations.

use std::time::Duration;

use crate::*;

pub(crate) async fn ipc_machines(action: Option<MachinesAction>) -> Result<()> {
    let request = match action {
        None => ipc::IpcMessage::ManagedMachines { probe: true },
        Some(MachinesAction::Enroll { reusable, expires }) => {
            let default = if reusable { "30d" } else { "7d" };
            let expires_secs = parse_duration_secs(expires.as_deref().unwrap_or(default))?;
            ipc::IpcMessage::MachineEnrollmentCreate {
                expires_in: Duration::from_secs(expires_secs),
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
    };
    let response = ipc_request(request).await?;
    match response {
        ipc::IpcMessage::ManagedMachinesResponse { machines } => {
            if json_enabled() {
                print_json(&serde_json::json!(machines));
            } else if machines.is_empty() {
                println!("no enrolled machines");
            } else {
                let rows = machines
                    .into_iter()
                    .map(|machine| {
                        let short_id = machine.identity.fmt_short().to_string();
                        let networks = machine
                            .networks
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ");
                        let state = match machine.state {
                            ipc::ManagedMachineState::Online => "online",
                            ipc::ManagedMachineState::Offline => "offline",
                            ipc::ManagedMachineState::Unauthorized => "unauthorized",
                            ipc::ManagedMachineState::Unknown => "unknown",
                        };
                        vec![
                            layout::Cell::new(
                                machine.hostname.to_string(),
                                style::value(machine.hostname.as_str()),
                            ),
                            layout::Cell::new(short_id.clone(), style::rose(&short_id)),
                            layout::Cell::new(state, style::faint(state)),
                            layout::Cell::new(networks.clone(), style::faint(&networks)),
                        ]
                    })
                    .collect();
                print!(
                    "{}",
                    table(&["machine", "id", "state", "networks"], rows, 2)
                );
            }
        }
        ipc::IpcMessage::MachineEnrollmentCreated {
            id,
            ticket,
            expires_at,
            reusable,
        } => {
            if json_enabled() {
                print_json(&serde_json::json!({
                    "id": id,
                    "ticket": ticket,
                    "expires_at": expires_at,
                    "reusable": reusable,
                }));
            } else {
                println!("enrollment {id}");
                println!("{ticket}");
                println!("run on the managed machine: ray up --controller {ticket}");
            }
        }
        ipc::IpcMessage::MachineEnrollments { enrollments } => {
            if json_enabled() {
                print_json(&serde_json::json!(enrollments));
            } else {
                for enrollment in enrollments {
                    let kind = if enrollment.reusable {
                        "reusable"
                    } else {
                        "one-time"
                    };
                    let status = match enrollment.status {
                        ipc::MachineEnrollmentStatus::Pending => "pending",
                        ipc::MachineEnrollmentStatus::Used => "used",
                        ipc::MachineEnrollmentStatus::Expired => "expired",
                        ipc::MachineEnrollmentStatus::Revoked => "revoked",
                    };
                    println!(
                        "{}  {}  {}  uses {}",
                        enrollment.id, kind, status, enrollment.uses
                    );
                }
            }
        }
        ipc::IpcMessage::Ok { message } => println!("{message}"),
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
                    if json_enabled() {
                        print_json(&serde_json::json!(controllers));
                    } else if controllers.is_empty() {
                        println!("no authorized controllers");
                    } else {
                        for controller in controllers {
                            println!(
                                "{}  {}",
                                controller.identity.fmt_short(),
                                controller.identity
                            );
                        }
                    }
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

async fn ipc_request(request: ipc::IpcMessage) -> Result<ipc::IpcMessage> {
    let mut stream = ipc::connect().await?;
    ipc::send(&mut stream, request).await?;
    ipc::recv(&mut stream).await
}

pub(crate) async fn ipc_management_overview()
-> (Vec<ipc::ControllerInfo>, Vec<ipc::ManagedMachineInfo>) {
    let controllers = async {
        match ipc_request(ipc::IpcMessage::ControllerList).await {
            Ok(ipc::IpcMessage::Controllers { controllers }) => controllers,
            _ => Vec::new(),
        }
    };
    let machines = async {
        match ipc_request(ipc::IpcMessage::ManagedMachines { probe: true }).await {
            Ok(ipc::IpcMessage::ManagedMachinesResponse { machines }) => machines,
            _ => Vec::new(),
        }
    };
    tokio::join!(controllers, machines)
}

fn print_simple_response(response: ipc::IpcMessage) -> Result<()> {
    match response {
        ipc::IpcMessage::Ok { message } => println!("{message}"),
        ipc::IpcMessage::Error { message } => fail_with("error", &message),
        other => fail_unexpected(&other),
    }
    Ok(())
}

fn result_message(response: ipc::IpcMessage) -> Result<String> {
    match response {
        ipc::IpcMessage::Ok { message } => Ok(message),
        ipc::IpcMessage::Error { message } => anyhow::bail!(message),
        other => anyhow::bail!(unexpected_detail(&other)),
    }
}
