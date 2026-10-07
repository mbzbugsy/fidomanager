use std::sync::Arc;

use fido_service::discovery_presentation::DiscoveryPresentation;
use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FoundationStatus {
    phase: &'static str,
    worker_protocol_version: u16,
    reviewed_libfido2_baseline: &'static str,
    inspection_activity: fido_service::activity::ActivityView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorList {
    enumeration_epoch: String,
    devices: Vec<AuthenticatorSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorSummary {
    inspection: fido_service::inspection::InspectionDisplay,
    display_name: String,
    display_detail: String,
    handle: String,
    generation: String,
    vendor_id: u16,
    product_id: u16,
    manufacturer: Option<String>,
    product: Option<String>,
    aaguid: Option<String>,
    versions: Vec<String>,
    extensions: Vec<String>,
    transports: Vec<String>,
    options: Vec<AuthenticatorOption>,
    max_message_size: Option<String>,
    firmware_version: Option<String>,
    read_status: String,
    freshness: String,
    pin_check_passed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatorOption {
    name: String,
    enabled: bool,
}

#[tauri::command]
pub fn foundation_status(state: tauri::State<'_, AppState>) -> FoundationStatus {
    let info = fido_service::foundation_info();
    FoundationStatus {
        phase: info.phase,
        worker_protocol_version: info.worker_protocol_version,
        reviewed_libfido2_baseline: info.reviewed_libfido2_baseline,
        inspection_activity: state.activity.view(),
    }
}

#[tauri::command]
pub async fn list_authenticators(
    state: tauri::State<'_, AppState>,
) -> Result<DiscoveryPresentation<AuthenticatorList>, ()> {
    let discovery = Arc::clone(&state.discovery);
    let inspection = Arc::clone(&state.inspection);
    let verification_history = Arc::clone(&state.verification_history);
    let activity = Arc::clone(&state.activity);
    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    let authority = Arc::clone(&state.authentication);
    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    let native_menu = state
        .authentication_menu
        .lock()
        .ok()
        .and_then(|m| m.clone());

    Ok(tauri::async_runtime::spawn_blocking(move || {
        let mut coordinator = discovery.lock().map_err(|_| ())?;
        // Lock order everywhere is discovery -> inspection. No renderer command takes a store
        // lock and then asks for discovery. Publish one coherent connected-device/inventory DTO.
        let snapshot = match coordinator.refresh() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let mut store = inspection.lock().map_err(|_| ())?;
                return Ok(store.discovery_problem(error));
            }
        };
        let worker = coordinator.status().worker_generation.ok_or(())?;
        let mut store = inspection.lock().map_err(|_| ())?;
        let inventory_devices = store
            .reconcile_connected(&snapshot.devices, worker)
            .map_err(|_| ())?;
        // Card continuity does not carry activity/problems across a connected generation.
        activity.retain_connected(&inventory_devices);
        let presentations =
            fido_service::presentation::authenticator_presentations(&snapshot.devices);
        // Keep history only for uniquely identified currently connected macOS IORegistry entries.
        // Markers remain backend-only: the renderer receives a historical boolean, never a path,
        // connection hash, acquisition or reusable approval.
        let mut present = std::collections::BTreeMap::new();
        for id in snapshot
            .devices
            .iter()
            .filter_map(|d| d.verification_history_id)
        {
            *present.entry(id).or_insert(0usize) += 1;
        }
        let passed = verification_history
            .lock()
            .map(|mut history| {
                history.retain(|id| present.get(id) == Some(&1));
                history.clone()
            })
            .unwrap_or_default();

        #[cfg(all(
            feature = "native-pin",
            not(feature = "native-ui-spike"),
            target_os = "macos"
        ))]
        if let Some(menu) = native_menu {
            menu.update(
                snapshot
                    .devices
                    .iter()
                    .zip(&presentations)
                    .flat_map(|(device, presentation)| {
                        crate::authentication::NativeTarget::for_device(device, presentation)
                    })
                    .collect(),
                &authority,
            );
        }

        let devices = snapshot
            .devices
            .into_iter()
            .zip(presentations)
            .zip(inventory_devices)
            .map(
                |((device, presentation), inventory_device)| AuthenticatorSummary {
                    inspection: store.display_for(inventory_device),
                    display_name: presentation.name,
                    display_detail: presentation.detail,
                    pin_check_passed: device
                        .verification_history_id
                        .is_some_and(|id| passed.contains(&id)),
                    handle: inventory_device.handle.as_wire(),
                    generation: inventory_device.generation.0.to_string(),
                    vendor_id: device.vendor_id,
                    product_id: device.product_id,
                    manufacturer: device.manufacturer,
                    product: device.product,
                    aaguid: device
                        .aaguid
                        .map(|value| format!("{:032x}", u128::from_be_bytes(*value.as_bytes()))),
                    versions: device.versions,
                    extensions: device.extensions,
                    transports: presentation.transports,
                    options: device
                        .options
                        .into_iter()
                        .map(|option| AuthenticatorOption {
                            name: option.name,
                            enabled: option.enabled,
                        })
                        .collect(),
                    max_message_size: device.max_message_size.map(|value| value.to_string()),
                    firmware_version: device.firmware_version.map(|value| value.to_string()),
                    read_status: device.read_status.as_wire_name().to_owned(),
                    freshness: device.freshness.as_wire_name().to_owned(),
                },
            )
            .collect();

        Ok(DiscoveryPresentation::Fresh {
            list: AuthenticatorList {
                enumeration_epoch: snapshot.enumeration_epoch.0.to_string(),
                devices,
            },
        })
    })
    .await
    .unwrap_or(Err(()))
    .unwrap_or_else(|()| {
        // Even lock poisoning/task failure must purge inventories and return no raw error text.
        state
            .inspection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        DiscoveryPresentation::Unavailable {}
    }))
}

/// BooGooCypher readiness status only. Takes no renderer input, reads no FIDO state and returns
/// a bare typed status. The backend serves a cached result and bounds any network request.
#[tauri::command]
pub async fn boogoocypher_status(
    state: tauri::State<'_, AppState>,
) -> Result<boogoocypher_status::ReadinessStatus, String> {
    let readiness = Arc::clone(&state.boogoocypher);
    Ok(readiness.status().await)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteCredentialRequest {
    #[serde(alias = "deviceHandle")]
    pub display_device_handle: fido_service::inspection::DisplayDeviceHandle,
    #[serde(
        alias = "generation",
        deserialize_with = "deserialize_device_generation"
    )]
    pub device_generation: fido_service::DeviceGeneration,
    #[serde(alias = "epoch")]
    pub enumeration_epoch: fido_service::inspection::EnumerationEpoch,
    #[serde(alias = "handle")]
    pub credential_handle: fido_service::inspection::CredentialHandle,
}

fn deserialize_device_generation<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<fido_service::DeviceGeneration, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = fido_service::DeviceGeneration;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u64 or numeric string")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(fido_service::DeviceGeneration(v))
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<u64>()
                .map(fido_service::DeviceGeneration)
                .map_err(E::custom)
        }
    }
    d.deserialize_any(Visitor)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteOutcome {
    ConfirmedSuccessful,
    WrongPin,
    PinBlocked,
    PinAuthBlocked,
    PinAuthInvalid,
    PinNotSet,
    PinRequired,
    UnauthorizedPermission,
    Parameters,
    CredentialAbsent,
    CredentialMismatch,
    NotDispatched,
    OutcomeUnknown,
    Cancelled,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteCredentialResponse {
    pub outcome: DeleteOutcome,
    pub message: String,
    pub recovery_required: bool,
}

#[tauri::command]
pub async fn delete_credential(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    request: DeleteCredentialRequest,
) -> Result<DeleteCredentialResponse, String> {
    let Some(claim) = state.activity.try_claim() else {
        return Ok(DeleteCredentialResponse {
            outcome: DeleteOutcome::NotDispatched,
            message: "Another security key operation is already in progress.".to_owned(),
            recovery_required: false,
        });
    };

    #[cfg(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    ))]
    {
        let discovery = Arc::clone(&state.discovery);
        let inspection_store = Arc::clone(&state.inspection);
        let authority = Arc::clone(&state.authentication);
        let native_menu = state
            .authentication_menu
            .lock()
            .ok()
            .and_then(|m| m.clone());

        let response = tauri::async_runtime::spawn_blocking(move || {
            let mut supervisor = match discovery.lock() {
                Ok(s) => s,
                Err(_) => {
                    claim.finish(fido_service::activity::ActivityOutcome::Issue(
                        fido_service::activity::RESTART_NEEDED,
                    ));
                    return DeleteCredentialResponse {
                        outcome: DeleteOutcome::NotDispatched,
                        message: "Discovery supervisor unavailable.".to_owned(),
                        recovery_required: false,
                    };
                }
            };

            let Some(_worker) = supervisor.status().worker_generation else {
                claim.finish(fido_service::activity::ActivityOutcome::Issue(
                    fido_service::activity::KEY_UNAVAILABLE,
                ));
                return DeleteCredentialResponse {
                    outcome: DeleteOutcome::NotDispatched,
                    message: "Security key worker unavailable.".to_owned(),
                    recovery_required: false,
                };
            };

            let target = {
                let store = match inspection_store.lock() {
                    Ok(s) => s,
                    Err(_) => {
                        claim.finish(fido_service::activity::ActivityOutcome::Issue(
                            fido_service::activity::RESTART_NEEDED,
                        ));
                        return DeleteCredentialResponse {
                            outcome: DeleteOutcome::NotDispatched,
                            message: "Inspection store unavailable.".to_owned(),
                            recovery_required: false,
                        };
                    }
                };
                match store.resolve_for_mutation(
                    request.display_device_handle,
                    request.device_generation,
                    &request.enumeration_epoch,
                    &request.credential_handle,
                ) {
                    Some(t) => t,
                    None => {
                        claim.finish(fido_service::activity::ActivityOutcome::Issue(
                            "Passkey is no longer valid or device state changed.",
                        ));
                        return DeleteCredentialResponse {
                            outcome: DeleteOutcome::NotDispatched,
                            message: "Passkey is no longer valid or device state changed. Inspect the security key again.".to_owned(),
                            recovery_required: false,
                        };
                    }
                }
            };

            claim.target(target.device());

            let mut inspection = match inspection_store.lock() {
                Ok(s) => s,
                Err(_) => {
                    claim.finish(fido_service::activity::ActivityOutcome::Issue(
                        fido_service::activity::RESTART_NEEDED,
                    ));
                    return DeleteCredentialResponse {
                        outcome: DeleteOutcome::NotDispatched,
                        message: "Inspection store unavailable.".to_owned(),
                        recovery_required: false,
                    };
                }
            };

            let presenter_app = app.clone();
            let workflow_result = authority.delete_credential(
                &mut supervisor,
                &mut inspection,
                target,
                move |prompt_request, controller, reply, presentation, retries, epoch, expected| {
                    let callback_app = presenter_app.clone();
                    presenter_app
                        .run_on_main_thread(move || {
                            let binding = prompt_request.binding();
                            if let Some(window) = callback_app.get_webview_window("main") {
                                if let Ok(parent) = window.ns_window() {
                                    let description = fido_service::deletion::deletion_description(
                                        presentation.authenticator(),
                                        presentation.rp_id(),
                                        presentation.user_name(),
                                        presentation.display_name(),
                                        presentation.credential_fingerprint(),
                                        presentation.inventory_incomplete(),
                                        Some(retries),
                                    );
                                    // SAFETY: live trusted main NSWindow on AppKit's main thread.
                                    if unsafe {
                                        fido_service::deletion::present_deletion(
                                            parent,
                                            prompt_request,
                                            Arc::clone(&controller),
                                            reply.clone(),
                                            Some(retries),
                                            (epoch, expected),
                                            &description,
                                        )
                                    }
                                    .is_ok()
                                    {
                                        return;
                                    }
                                }
                            }
                            fido_service::deletion::deletion_presentation_failed(
                                binding, controller, reply,
                            );
                        })
                        .map_err(|_| "main thread unavailable")
                },
            );

            if let Some(menu) = &native_menu {
                menu.update(Vec::new(), &authority);
            }

            let (response, activity_outcome) = map_workflow_result(workflow_result);
            claim.finish(activity_outcome);
            response
        })
        .await
        .map_err(|e| e.to_string())?;

        Ok(response)
    }

    #[cfg(not(all(
        feature = "native-pin",
        not(feature = "native-ui-spike"),
        target_os = "macos"
    )))]
    {
        let _ = (app, state, request);
        claim.finish(fido_service::activity::ActivityOutcome::Issue(
            "Credential deletion is only supported on macOS with native-pin.",
        ));
        Ok(DeleteCredentialResponse {
            outcome: DeleteOutcome::NotDispatched,
            message: "Credential deletion is only supported on macOS with native-pin.".to_owned(),
            recovery_required: false,
        })
    }
}

pub(crate) fn map_workflow_result(
    workflow_result: Result<
        fido_service::deletion::DeleteCredentialWorkflowResult,
        fido_service::deletion::DeleteCredentialError,
    >,
) -> (
    DeleteCredentialResponse,
    fido_service::activity::ActivityOutcome,
) {
    match workflow_result {
        Ok(res) => {
            if res.cancelled {
                (
                    DeleteCredentialResponse {
                        outcome: DeleteOutcome::Cancelled,
                        message: "Credential deletion was cancelled.".to_owned(),
                        recovery_required: false,
                    },
                    fido_service::activity::ActivityOutcome::Cancelled,
                )
            } else {
                match res.outcome {
                    fido_service::MutationOutcome::ConfirmedSuccessful => (
                        DeleteCredentialResponse {
                            outcome: DeleteOutcome::ConfirmedSuccessful,
                            message: "The passkey was deleted from this security key. Your website account was not deleted or modified.".to_owned(),
                            recovery_required: false,
                        },
                        fido_service::activity::ActivityOutcome::Success(
                            "Passkey deleted from security key.",
                        ),
                    ),
                    fido_service::MutationOutcome::Rejected => {
                        let (outcome, msg, issue_msg) = match res.rejection {
                            Some(fido_service::deletion::DeleteCredentialRejection::WrongPin) => (
                                DeleteOutcome::WrongPin,
                                "Incorrect PIN. No passkeys were deleted.",
                                "Incorrect PIN.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::PinBlocked) => (
                                DeleteOutcome::PinBlocked,
                                "PIN is blocked by the security key. No passkeys were deleted.",
                                "PIN is blocked.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::PinAuthBlocked) => (
                                DeleteOutcome::PinAuthBlocked,
                                "PIN authentication is temporarily blocked by the security key. No passkeys were deleted.",
                                "PIN authentication is temporarily blocked.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::PinAuthInvalid) => (
                                DeleteOutcome::PinAuthInvalid,
                                "PIN authentication was rejected by the security key. No passkeys were deleted.",
                                "PIN authentication was rejected.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::PinNotSet) => (
                                DeleteOutcome::PinNotSet,
                                "No PIN is set on this security key. No passkeys were deleted.",
                                "No PIN is set.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::PinRequired) => (
                                DeleteOutcome::PinRequired,
                                "A PIN is required by this security key. No passkeys were deleted.",
                                "A PIN is required.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::UnauthorizedPermission) => (
                                DeleteOutcome::UnauthorizedPermission,
                                "Permission unauthorized by security key. No passkeys were deleted.",
                                "Permission unauthorized.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::Parameters) => (
                                DeleteOutcome::Parameters,
                                "Security key rejected credential deletion parameters. No passkeys were deleted.",
                                "Invalid parameters.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::CredentialAbsent) => (
                                DeleteOutcome::CredentialAbsent,
                                "The passkey could no longer be confirmed on this security key. Inspect the key again to view current passkeys.",
                                "Passkey could no longer be confirmed on this key.",
                            ),
                            Some(fido_service::deletion::DeleteCredentialRejection::CredentialMismatch) => (
                                DeleteOutcome::CredentialMismatch,
                                "Passkey information changed or could not be safely matched. Inspect the security key again before attempting deletion.",
                                "Passkey information changed or could not be safely matched.",
                            ),
                            None => (
                                DeleteOutcome::NotDispatched,
                                "The security key rejected credential deletion. No passkeys were deleted.",
                                "Credential deletion rejected.",
                            ),
                        };
                        (
                            DeleteCredentialResponse {
                                outcome,
                                message: msg.to_owned(),
                                recovery_required: false,
                            },
                            fido_service::activity::ActivityOutcome::Issue(issue_msg),
                        )
                    }
                    fido_service::MutationOutcome::OutcomeUnknown => (
                        DeleteCredentialResponse {
                            outcome: DeleteOutcome::OutcomeUnknown,
                            message: "Could not determine whether the passkey was deleted. Do not retry deletion. Review uncertainty in the Security key menu.".to_owned(),
                            recovery_required: true,
                        },
                        fido_service::activity::ActivityOutcome::Issue(
                            "Credential deletion unconfirmed. Review the Security key menu.",
                        ),
                    ),
                    fido_service::MutationOutcome::NotDispatched => (
                        DeleteCredentialResponse {
                            outcome: DeleteOutcome::NotDispatched,
                            message: "Credential deletion was not dispatched. No changes were made.".to_owned(),
                            recovery_required: false,
                        },
                        fido_service::activity::ActivityOutcome::Issue(
                            "Credential deletion was not dispatched.",
                        ),
                    ),
                }
            }
        }
        Err(err) => {
            let recovery_required = matches!(
                err,
                fido_service::deletion::DeleteCredentialError::Journal(_)
            );
            let (outcome, msg, issue_msg) = if recovery_required {
                (
                    DeleteOutcome::OutcomeUnknown,
                    "Storage error during credential deletion. Do not retry deletion. Review uncertainty in the Security key menu.",
                    "Storage error during deletion. Review the Security key menu.",
                )
            } else {
                (
                    DeleteOutcome::NotDispatched,
                    "Credential deletion was not dispatched.",
                    "Credential deletion could not start.",
                )
            };
            (
                DeleteCredentialResponse {
                    outcome,
                    message: msg.to_owned(),
                    recovery_required,
                },
                fido_service::activity::ActivityOutcome::Issue(issue_msg),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_service::MutationOutcome;
    use fido_service::deletion::{
        DeleteCredentialError, DeleteCredentialRejection, DeleteCredentialWorkflowResult,
    };

    #[test]
    fn request_deserialization_from_wire() -> Result<(), serde_json::Error> {
        let json = r#"{
            "displayDeviceHandle": "00000000000000000000000000000001",
            "deviceGeneration": "2",
            "enumerationEpoch": "epoch-xyz",
            "credentialHandle": "cred-abc"
        }"#;
        let req: DeleteCredentialRequest = serde_json::from_str(json)?;
        assert_eq!(req.device_generation, fido_service::DeviceGeneration(2));
        assert_eq!(req.enumeration_epoch.as_wire(), "epoch-xyz");
        assert_eq!(req.credential_handle.as_wire(), "cred-abc");

        // Numeric deviceGeneration and aliased field names
        let json_aliased = r#"{
            "deviceHandle": "00000000000000000000000000000001",
            "generation": 3,
            "epoch": "epoch-123",
            "handle": "cred-789"
        }"#;
        let req_aliased: DeleteCredentialRequest = serde_json::from_str(json_aliased)?;
        assert_eq!(
            req_aliased.device_generation,
            fido_service::DeviceGeneration(3)
        );
        assert_eq!(req_aliased.enumeration_epoch.as_wire(), "epoch-123");
        assert_eq!(req_aliased.credential_handle.as_wire(), "cred-789");
        Ok(())
    }

    #[test]
    fn request_rejects_hostile_and_raw_fields() {
        let bad_fields = [
            r#"{"displayDeviceHandle": "00000000000000000000000000000001", "deviceGeneration": "1", "enumerationEpoch": "e", "credentialHandle": "c", "credentialId": "deadbeef"}"#,
            r#"{"displayDeviceHandle": "00000000000000000000000000000001", "deviceGeneration": "1", "enumerationEpoch": "e", "credentialHandle": "c", "userId": "1234"}"#,
            r#"{"displayDeviceHandle": "00000000000000000000000000000001", "deviceGeneration": "1", "enumerationEpoch": "e", "credentialHandle": "c", "rpHash": "abcd"}"#,
            r#"{"displayDeviceHandle": "00000000000000000000000000000001", "deviceGeneration": "1", "enumerationEpoch": "e", "credentialHandle": "c", "nativeHandle": 1}"#,
            r#"{"displayDeviceHandle": "00000000000000000000000000000001", "deviceGeneration": "1", "enumerationEpoch": "e", "credentialHandle": "c", "pin": "123456"}"#,
            r#"{"displayDeviceHandle": "00000000000000000000000000000001", "deviceGeneration": "1", "enumerationEpoch": "e", "credentialHandle": "c", "permit": "token"}"#,
        ];
        for bad in bad_fields {
            let res: Result<DeleteCredentialRequest, _> = serde_json::from_str(bad);
            assert!(res.is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn response_serialization_contract() -> Result<(), Box<dyn std::error::Error>> {
        let res = DeleteCredentialResponse {
            outcome: DeleteOutcome::ConfirmedSuccessful,
            message: "Deleted".to_string(),
            recovery_required: false,
        };
        let val: serde_json::Value = serde_json::to_value(&res)?;
        let obj = val.as_object().ok_or("expected json object")?;
        assert_eq!(obj.len(), 3);
        assert!(obj.contains_key("outcome"));
        assert!(obj.contains_key("message"));
        assert!(obj.contains_key("recoveryRequired"));
        Ok(())
    }

    #[test]
    fn safe_debug_representations() -> Result<(), serde_json::Error> {
        let json = r#"{
            "displayDeviceHandle": "00000000000000000000000000000001",
            "deviceGeneration": "1",
            "enumerationEpoch": "epoch-safe",
            "credentialHandle": "cred-safe"
        }"#;
        let req: DeleteCredentialRequest = serde_json::from_str(json)?;
        let debug = format!("{req:?}");
        assert!(!debug.contains("pin"));
        assert!(!debug.contains("secret"));

        let res = DeleteCredentialResponse {
            outcome: DeleteOutcome::WrongPin,
            message: "Incorrect PIN. No passkeys were deleted.".to_string(),
            recovery_required: false,
        };
        let res_debug = format!("{res:?}");
        assert!(!res_debug.contains("secret"));
        Ok(())
    }

    #[test]
    fn cancel_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::NotDispatched,
            rejection: None,
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: false,
            cancelled: true,
        };
        let (mapped, act) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::Cancelled);
        assert!(!mapped.recovery_required);
        assert!(mapped.message.contains("cancelled"));
        assert_eq!(act, fido_service::activity::ActivityOutcome::Cancelled);
    }

    #[test]
    fn wrong_pin_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::Rejected,
            rejection: Some(DeleteCredentialRejection::WrongPin),
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: false,
            cancelled: false,
        };
        let (mapped, act) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::WrongPin);
        assert!(!mapped.recovery_required);
        assert!(mapped.message.contains("Incorrect PIN"));
        assert!(mapped.message.contains("No passkeys were deleted"));
        assert_eq!(
            act,
            fido_service::activity::ActivityOutcome::Issue("Incorrect PIN.")
        );
    }

    #[test]
    fn pin_blocked_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::Rejected,
            rejection: Some(DeleteCredentialRejection::PinBlocked),
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: false,
            cancelled: false,
        };
        let (mapped, _) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::PinBlocked);
        assert!(!mapped.recovery_required);
        assert!(mapped.message.contains("blocked"));
    }

    #[test]
    fn credential_absent_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::Rejected,
            rejection: Some(DeleteCredentialRejection::CredentialAbsent),
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: false,
            cancelled: false,
        };
        let (mapped, _) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::CredentialAbsent);
        assert!(!mapped.recovery_required);
        assert!(mapped.message.contains("could no longer be confirmed"));
        assert!(mapped.message.contains("Inspect the key again"));
    }

    #[test]
    fn credential_mismatch_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::Rejected,
            rejection: Some(DeleteCredentialRejection::CredentialMismatch),
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: false,
            cancelled: false,
        };
        let (mapped, _) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::CredentialMismatch);
        assert!(!mapped.recovery_required);
        assert!(
            mapped
                .message
                .contains("changed or could not be safely matched")
        );
        assert!(mapped.message.contains("Inspect the security key again"));
    }

    #[test]
    fn not_dispatched_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::NotDispatched,
            rejection: None,
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: false,
            cancelled: false,
        };
        let (mapped, _) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::NotDispatched);
        assert!(!mapped.recovery_required);
        assert!(mapped.message.contains("was not dispatched"));
    }

    #[test]
    fn confirmed_successful_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::ConfirmedSuccessful,
            rejection: None,
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: false,
            cancelled: false,
        };
        let (mapped, act) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::ConfirmedSuccessful);
        assert!(!mapped.recovery_required);
        assert!(
            mapped
                .message
                .contains("was deleted from this security key")
        );
        assert!(
            mapped
                .message
                .contains("account was not deleted or modified")
        );
        assert_eq!(
            act,
            fido_service::activity::ActivityOutcome::Success("Passkey deleted from security key.")
        );
    }

    #[test]
    fn outcome_unknown_and_recovery_required_result_mapping() {
        let res = DeleteCredentialWorkflowResult {
            outcome: MutationOutcome::OutcomeUnknown,
            rejection: None,
            worker_quiescent: true,
            prompt_torn_down: true,
            recovery_required: true,
            cancelled: false,
        };
        let (mapped, _) = map_workflow_result(Ok(res));
        assert_eq!(mapped.outcome, DeleteOutcome::OutcomeUnknown);
        assert!(mapped.recovery_required);
        assert!(
            mapped
                .message
                .contains("Could not determine whether the passkey was deleted")
        );
        assert!(mapped.message.contains("Do not retry deletion"));
        assert!(mapped.message.contains("Security key menu"));
    }

    #[test]
    fn journal_storage_error_mapping() {
        let err = DeleteCredentialError::Journal(fido_service::recovery::JournalError::Unavailable);
        let (mapped, act) = map_workflow_result(Err(err));
        assert_eq!(mapped.outcome, DeleteOutcome::OutcomeUnknown);
        assert!(mapped.recovery_required);
        assert!(
            mapped
                .message
                .contains("Storage error during credential deletion")
        );
        assert!(mapped.message.contains("Do not retry deletion"));
        assert!(mapped.message.contains("Security key menu"));
        assert_eq!(
            act,
            fido_service::activity::ActivityOutcome::Issue(
                "Storage error during deletion. Review the Security key menu."
            )
        );
    }

    #[test]
    fn invalid_permit_error_mapping() {
        let err = DeleteCredentialError::InvalidPermit;
        let (mapped, act) = map_workflow_result(Err(err));
        assert_eq!(mapped.outcome, DeleteOutcome::NotDispatched);
        assert!(!mapped.recovery_required);
        assert!(mapped.message.contains("was not dispatched"));
        assert_eq!(
            act,
            fido_service::activity::ActivityOutcome::Issue("Credential deletion could not start.")
        );
    }

    #[test]
    fn parallel_workflow_prevention() {
        let tracker = std::sync::Arc::new(fido_service::activity::ActivityTracker::default());
        let claim1 = tracker.try_claim();
        assert!(claim1.is_some());
        let claim2 = tracker.try_claim();
        assert!(claim2.is_none(), "second concurrent claim must fail");
        drop(claim1);
        let claim3 = tracker.try_claim();
        assert!(claim3.is_some(), "claim is available after release");
    }
}
