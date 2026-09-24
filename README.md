# Lumi Agents Control Plane

A fast, edge-native organization control plane for Lumi Agents.

## Architecture

```text
apps/web  ── /api/* ──>  apps/api
React 19.3              Rust + Axum
Vite 8                  Cloudflare Workers
shadcn/Base UI          workers-rs
Tailwind CSS 4
```

The repository deliberately starts with **one web app and one API worker**. We use pnpm workspaces + Cargo workspaces and avoid an additional task orchestrator until the repository is large enough for remote task caching to pay for its complexity.

## Stack

- Rust + Axum 0.8 on Cloudflare Workers via `workers-rs`
- React 19.3 + Vite 8 + TypeScript 7
- shadcn/ui using **Base UI**, never Radix
- Tailwind CSS 4
- pnpm 12
- Oxlint + Oxfmt
- Vitest
- Wrangler 4

## Start

Prerequisites: Node 24 LTS, pnpm 12, stable Rust, and `wasm32-unknown-unknown`.

```bash
corepack enable
pnpm install
rustup target add wasm32-unknown-unknown
cargo install --locked worker-build --version "^0.8"
pnpm dev
```

- Web: http://localhost:5173
- API: http://localhost:8787
- Health through web proxy: http://localhost:5173/api/health

## Quality

```bash
pnpm format
pnpm lint
pnpm typecheck
pnpm test
pnpm rust:check
pnpm check
```

Read `AGENTS.md` and `docs/adr/` before substantial work.

> Bootstrap note: this scaffold was created through the GitHub API, so no package manager was executed while writing it. The first working checkout MUST run `pnpm install`, commit `pnpm-lock.yaml`, and only then enable CI with `--frozen-lockfile`.
