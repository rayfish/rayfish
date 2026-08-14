#![cfg(windows)]

//! Windows adapter contracts that do not require Administrator, Wintun, or a
//! live mesh. Privileged MSI/service/DNS tests stay in the manual lane.

#[test]
fn console_process_does_not_claim_windows_service_dispatch() {
    assert!(
        !rayfish::windows_service::run_if_service()
            .expect("console invocation should return the dispatcher fallback")
    );
}
