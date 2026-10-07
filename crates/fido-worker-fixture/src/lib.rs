//! Synthetic credential evidence shared by deterministic process fixtures. Never shipped.
pub fn inventory() -> fido_core::inventory::OwnedInventory {
    use fido_core::inventory::*;
    OwnedInventory {
        metadata_existing: 1,
        rps: vec![OwnedRp {
            hash: [
                163, 121, 166, 246, 238, 175, 185, 165, 94, 55, 140, 17, 128, 52, 226, 117, 30,
                104, 47, 171, 159, 45, 48, 171, 19, 210, 18, 85, 134, 206, 25, 71,
            ],
            verified_text: Some("example.com".into()),
            issue: None,
            credentials: vec![OwnedCredential {
                id: vec![17, 19, 23],
                user_id: Some(vec![29, 31, 37]),
                user_name: Some("person@example.com".into()),
                display_name: Some("Person".into()),
            }],
        }],
    }
}
