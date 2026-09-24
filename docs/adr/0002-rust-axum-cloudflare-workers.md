# ADR 0002: Rust + Axum on Cloudflare Workers

- Status: Accepted
- Date: 2026-09-24

## Context

The API must be globally deployable, resource-efficient, and straightforward to extend. Cloudflare's Rust SDK supports standard HTTP types and an Axum bridge.

## Decision

Use `workers-rs`, the `worker` crate's `http` + `axum` features, Axum 0.8 with only required features, `tower-service`, `wasm32-unknown-unknown`, and `worker-build` through Wrangler.

Keep one modular Worker until scale, ownership, or security boundaries justify another deployable.

## Runtime constraints

Workers are not a Linux server.

- Do not assume Tokio exists.
- Every crate must compile for WASM.
- Avoid filesystem/process/thread assumptions.
- Avoid large dependency trees.
- Use Cloudflare bindings through small adapters.
- Put retryable/long-running work into Queues/Workflows when introduced.

## Dependency direction

```text
fetch -> Axum router -> transport/validation -> application/domain -> ports -> Cloudflare adapters
```

Raw `Env` should not leak through domain code.

## WASM profile

The release profile favors compact output: LTO, one codegen unit, `opt-level = "s"`, debug information stripped, panic abort. Do not use `strip = true` or strip symbols: wasm-bindgen 0.2.125+ needs the externref table to generate catch wrappers, and full stripping removes it. The Worker dry-run is the authority for validating changes to these flags.

Move toward a speed-optimized profile only after a benchmark shows user-visible benefit that outweighs artifact/startup cost.

## Build-time note

Compiling `worker-build` from scratch can dominate clean CI. Cache Cargo artifacts and install the compatible worker-build once per CI environment.

## Primary failure mode

A familiar server-side crate may depend on OS or Tokio behavior. A host build can look fine while the Worker target fails or bloats. WASM target checks are mandatory.
