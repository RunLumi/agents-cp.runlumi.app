# Lumi Agents Control Plane

Fast, edge-native control plane for Lumi Agents.

## Stack

- **Backend:** Rust + Axum on Cloudflare Workers (workers-rs)
- **Frontend:** React 19 + Vite 8 + TypeScript 7
- **UI:** shadcn/ui on **Base UI** + Tailwind CSS 4 + Tabler Icons
- **Repo:** pnpm workspace + Cargo workspace
- **Testing:** Rust tests + Vitest + Playwright
- **Deploy:** Cloudflare Workers

The repository is intentionally small at the root and explicit at package boundaries. See `AGENTS.md` and `docs/adr/` before adding infrastructure or dependencies.
