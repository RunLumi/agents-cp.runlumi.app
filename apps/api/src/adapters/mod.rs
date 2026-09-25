pub mod crypto;
pub mod d1;
mod email;
pub mod password;
mod platform;
pub mod providers;
pub mod queues;
pub mod webauthn;

pub(crate) use email::deliver_auth_code;
pub(crate) use platform::{
    add_idempotency_ttl, add_seconds, new_event_id, new_resource_id, new_secret, sha256_hex,
    verify_device_proof,
};
