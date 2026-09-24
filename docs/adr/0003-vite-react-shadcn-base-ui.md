# ADR 0003: Vite + React + shadcn on Base UI

- Status: Accepted
- Date: 2026-09-24

## Decision

Use React 19.3, Vite 8, `@vitejs/plugin-react` 6, TypeScript 7, Tailwind CSS 4, shadcn/ui with **Base UI**, and Tabler as the preferred icon library.

Radix UI is excluded.

## Why Vite 8

Vite 8 uses Rolldown for production bundling and its React plugin uses Oxc for React Refresh transforms. This directly serves the short edit-feedback loop we want.

Browser console forwarding is enabled so coding agents receive runtime browser failures in their terminal.

## Why Base UI

shadcn made Base UI the default primitive layer for new projects in 2026. It is unstyled, accessible, tree-shakable, and lets Lumi own its visual language.

`components.json` is authoritative. Generated components must use `@base-ui/react`; `@radix-ui/*` requires superseding this ADR.

## Experimental features

Do not enable the Rust React Compiler globally yet. The Vite plugin marks it experimental.

Do not enable Vite's experimental bundled dev mode globally while the module graph is small.

Both are benchmark-gated options if profiling later shows a real problem.

## Styling

- semantic CSS variables for durable tokens;
- Tailwind for composition/layout/state;
- Base UI for interaction primitives;
- shadcn component source stays editable inside the repo;
- avoid animation libraries until a real interaction requires one;
- prefer platform fonts unless brand typography creates enough value to justify startup cost.
