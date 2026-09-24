# ADR 0001: Monorepo and toolchain

- Status: Accepted
- Date: 2026-09-24

## Context

The control plane starts with two deployables: one Rust Worker API and one Vite React web app. The priority is a short feedback loop without an orchestration system agents must first understand.

## Decision

Use pnpm workspaces for JS/TS, Cargo workspaces for Rust, Node 24 LTS, TypeScript 7, Oxlint/Oxfmt, Cargo fmt, and Clippy.

Do **not** add Turborepo or Nx now. Do **not** create generic shared packages before two real consumers exist.

## Why

A task graph/cache layer pays for itself when many packages repeatedly rebuild. With one JS app and one Rust app it adds configuration, cache semantics, and agent context without removing a meaningful bottleneck.

pnpm gives strict declared dependencies, workspace support, content-addressed storage, and deterministic installs once `pnpm-lock.yaml` is committed.

## Consequences

Positive: fewer moving parts, clear boundaries, fast local iteration.

Negative: no remote task cache initially and root scripts perform simple orchestration.

## Revisit

Evaluate a task runner when at least one becomes true:

- 4+ independently built JS packages/apps;
- CI materially rebuilds unchanged JS tasks;
- remote caching shows measured payback;
- task ordering becomes hard to express safely with pnpm filters.
