//! Private R2 export-artifact adapter (ADR 0006).
//!
//! The adapter is deliberately tiny and is the *only* module in the crate that
//! holds an R2 handle. Nothing here builds a URL: ADR 0006 rejects a public
//! bucket, a permanent object URL, and a presigned bearer URL, so the only way
//! an export artifact leaves Lumi is the Worker-mediated download route, which
//! re-authorizes the principal, the job scope, the job state, and the expiry
//! and then streams the body.
//!
//! Invariants this adapter keeps:
//!
//! * **No secret in object metadata.** `put` sets only HTTP content metadata.
//!   R2 custom metadata is never populated, so an authorization header, a
//!   prompt, or a credential cannot reach the bucket through this path.
//! * **Opaque keys.** Keys are server-generated and carry a CSPRNG segment.
//!   The `org_`/`exp_` prefix is authorization metadata for humans debugging a
//!   key, never an access token.
//! * **Bounded bodies.** `get` is only used to produce a streaming response.
//!   Nothing in this module calls `text()`, `bytes()`, or `arrayBuffer()` on
//!   an object, so an unbounded export is never buffered in Worker memory.
//! * **Idempotent delete.** `delete` reports whether the object existed and
//!   `is_absent` is a real `head` probe, so a deletion certificate can verify
//!   object absence instead of assuming D1 metadata is sufficient evidence.
//!
//! Application-level envelope encryption is intentionally *not* added here: R2's
//! managed encryption at rest plus the private binding is the ADR 0006 baseline,
//! and adding a ciphertext envelope would change the public artifact format.
//! Revisit only with a concrete threat model (ADR 0006 "Implementation
//! constraints").

mod artifacts;

pub use artifacts::{
    ALLOWED_CONTENT_TYPES as ARTIFACT_CONTENT_TYPES, ARTIFACT_BINDING, ARTIFACT_KEY_PREFIX,
    ArtifactError, ArtifactHead, ExportArtifactStore, ObjectKey, PutArtifact, StoredObject,
    StreamDescriptor, build_object_key, hex_decode, hex_encode, is_valid_object_key,
};
