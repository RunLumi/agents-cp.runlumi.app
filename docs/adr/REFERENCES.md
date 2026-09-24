# Architecture research references

Verified for the initial scaffold on 2026-09-24. Prefer these primary sources when revisiting the corresponding ADR.

## Cloudflare Workers + Rust

- Cloudflare Rust language guide: https://developers.cloudflare.com/workers/languages/rust/
- workers-rs repository: https://github.com/cloudflare/workers-rs
- workers-rs Axum example: https://github.com/cloudflare/workers-rs/tree/main/examples/axum
- Wrangler configuration: https://developers.cloudflare.com/workers/wrangler/configuration/

Key constraint: Cloudflare's Axum example uses the workers-rs HTTP/Axum bridge and Axum with minimal features. Worker dependencies must remain compatible with `wasm32-unknown-unknown`.

## Vite + React

- Vite 8 announcement: https://vite.dev/blog/announcing-vite8
- Vite server options, including agent-friendly `server.forwardConsole`: https://vite.dev/config/server-options
- Vite performance guide: https://vite.dev/guide/performance
- @vitejs/plugin-react: https://www.npmjs.com/package/@vitejs/plugin-react
- React releases: https://react.dev/versions

Vite's experimental bundled dev mode and the Rust React Compiler remain opt-in, benchmark-gated choices.

## shadcn + Base UI

- shadcn Base UI announcement: https://ui.shadcn.com/docs/changelog/2026-07-base-ui-default
- shadcn Vite install: https://ui.shadcn.com/docs/installation/vite
- shadcn monorepo guide: https://ui.shadcn.com/docs/monorepo
- Base UI: https://base-ui.com/
- Base UI package: https://www.npmjs.com/package/@base-ui/react

The project standard is **Base UI, not Radix**.

## Toolchain

- pnpm workspaces: https://pnpm.io/workspaces
- TypeScript: https://www.typescriptlang.org/
- Oxlint: https://oxc.rs/docs/guide/usage/linter
- Oxfmt: https://oxc.rs/docs/guide/usage/formatter
- Vitest: https://vitest.dev/
- Playwright best practices: https://playwright.dev/docs/best-practices

## Revalidation rule

Before a major upgrade, check current upstream release notes and compatibility rather than copying versions from this file.
