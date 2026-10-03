//! Human-facing metadata only. These labels never identify or authorize a physical key.

use std::collections::BTreeMap;

use fido_core::DeviceSnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatorPresentation {
    pub name: String,
    pub detail: String,
    pub transports: Vec<String>,
}

impl AuthenticatorPresentation {
    pub fn label(&self) -> String {
        format!("{} · {}", self.name, self.detail)
    }
}

fn display_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn name_or(value: Option<&str>, fallback: &str) -> String {
    value
        .map(display_text)
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

/// Canonical display order: USB, NFC, Bluetooth, internal, hybrid, then unknown names.
/// GetInfo transports describe supported capabilities, not a unique unit or active connection.
pub fn transport_labels(transports: &[String]) -> Vec<String> {
    let mut labels: Vec<_> = transports
        .iter()
        .map(|value| display_text(value).to_lowercase())
        .filter(|value| !value.is_empty())
        .map(|value| match value.as_str() {
            "usb" => (0, "USB".to_owned()),
            "nfc" => (1, "NFC".to_owned()),
            "ble" => (2, "Bluetooth LE".to_owned()),
            "internal" => (3, "Internal".to_owned()),
            "hybrid" => (4, "Hybrid".to_owned()),
            _ => (5, value.to_uppercase()),
        })
        .collect();
    labels.sort();
    labels.dedup();
    labels.into_iter().map(|(_, label)| label).collect()
}

/// Corresponds positionally to this snapshot only. Duplicate labels receive temporary Key N
/// numbering in enumeration order. Never persist it or use it for routing/authorization.
/// Handles, generations, AAGUIDs and connection-history identifiers are deliberately not read.
pub fn authenticator_presentations(devices: &[DeviceSnapshot]) -> Vec<AuthenticatorPresentation> {
    let mut presentations: Vec<_> = devices
        .iter()
        .map(|device| {
            let transports = transport_labels(&device.transports);
            let summary = if transports.is_empty() {
                "Transports not reported".to_owned()
            } else {
                transports.join(" + ")
            };
            AuthenticatorPresentation {
                name: name_or(device.product.as_deref(), "Security key"),
                detail: format!(
                    "{} · {summary}",
                    name_or(device.manufacturer.as_deref(), "Unknown manufacturer")
                ),
                transports,
            }
        })
        .collect();
    let mut counts = BTreeMap::new();
    for presentation in &presentations {
        *counts.entry(presentation.label()).or_insert(0usize) += 1;
    }
    let mut numbers = BTreeMap::new();
    for presentation in &mut presentations {
        let label = presentation.label();
        if counts.get(&label).is_some_and(|count| *count > 1) {
            let number = numbers.entry(label).or_insert(0usize);
            *number += 1;
            presentation.detail.push_str(&format!(" · Key {number}"));
        }
    }
    presentations
}

#[cfg(test)]
mod tests {
    use super::*;
    use fido_core::{Aaguid, DeviceGeneration, DeviceHandle, DeviceReadStatus, ViewFreshness};

    fn device(handle: u128, transports: &[&str]) -> DeviceSnapshot {
        DeviceSnapshot {
            verification_history_id: None,
            handle: DeviceHandle::from_raw(handle),
            generation: DeviceGeneration(1),
            vendor_id: 0x1ea8,
            product_id: 0xf829,
            manufacturer: Some("Thetis".to_owned()),
            product: Some("Security Key(F829)".to_owned()),
            aaguid: None,
            versions: Vec::new(),
            extensions: Vec::new(),
            transports: transports.iter().map(|value| (*value).to_owned()).collect(),
            options: Vec::new(),
            max_message_size: None,
            firmware_version: None,
            read_status: DeviceReadStatus::Ready,
            freshness: ViewFreshness::Fresh,
        }
    }

    #[test]
    fn variants_use_metadata_without_ephemeral_identity() {
        let mut devices = [device(9, &["usb"]), device(10, &["nfc", "usb"])];
        let labels = authenticator_presentations(&devices);
        assert_eq!(labels[0].name, "Security Key(F829)");
        assert_eq!(labels[0].detail, "Thetis · USB");
        assert_eq!(labels[1].detail, "Thetis · USB + NFC");
        for (index, device) in devices.iter_mut().enumerate() {
            assert!(!labels[index].label().contains("session"));
            assert!(
                !labels[index]
                    .label()
                    .contains(&format!("{:08x}", device.handle.as_raw()))
            );
            device.handle = DeviceHandle::from_raw(100 + index as u128);
            device.generation = DeviceGeneration(99);
            device.aaguid = Some(Aaguid::from_bytes([index as u8; 16]));
            device.verification_history_id = Some([index as u8; 32]);
        }
        assert_eq!(authenticator_presentations(&devices), labels);
    }

    #[test]
    fn transport_order_is_deterministic_and_unknown_values_are_retained() {
        let a = ["nfc", "usb", "ble", "hybrid", "internal", "zeta", "alpha"];
        let first = device(1, &a);
        let mut second = first.clone();
        second.transports.reverse();
        second.transports.push("USB".to_owned());
        assert_eq!(
            transport_labels(&first.transports),
            transport_labels(&second.transports)
        );
        assert_eq!(
            transport_labels(&first.transports),
            [
                "USB",
                "NFC",
                "Bluetooth LE",
                "Internal",
                "Hybrid",
                "ALPHA",
                "ZETA"
            ]
        );
    }

    #[test]
    fn duplicate_numbering_is_snapshot_presentation_only() {
        let first = device(9, &["usb"]);
        let mut second = device(10, &["usb"]);
        second.aaguid = Some(Aaguid::from_bytes([1; 16]));
        let devices = [first.clone(), second];
        let labels = authenticator_presentations(&devices);
        assert_eq!(labels[0].detail, "Thetis · USB · Key 1");
        assert_eq!(labels[1].detail, "Thetis · USB · Key 2");
        assert_eq!(devices[0].handle, first.handle);
        assert_eq!(
            authenticator_presentations(&[first])[0].detail,
            "Thetis · USB"
        );
    }

    #[test]
    fn empty_or_control_metadata_has_safe_generic_fallbacks() {
        let mut device = device(1, &[]);
        device.product = Some("\n\t".to_owned());
        device.manufacturer = None;
        let label = authenticator_presentations(&[device]).remove(0);
        assert_eq!(label.name, "Security key");
        assert_eq!(
            label.detail,
            "Unknown manufacturer · Transports not reported"
        );
    }
}
