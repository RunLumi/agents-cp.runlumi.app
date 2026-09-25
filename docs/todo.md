# Product and Engineering To-do

- [ ] **Explore protocol-first extensibility and live updates**
  - Evaluate a versioned LumiAgents server/client protocol that can support independent, polished custom frontends. Use OpenCode and OpenChamber as references, without assuming Lumi should adopt their protocol.
  - Define how saved changes to skills, agents, MCP servers, and plugins can take effect without restarting the app, including validation, policy/approval checks, rollback, and behavior for active sessions.
  - Prototype one alternate client and one live extension update against a versioned contract before committing to product scope.
  - Related contracts: [F13 — Tools, MCP, Browser & Computer Use Policies](specs/f13-tools-mcp-browser-computer-use-policies.md), [F25 — Plugins, Extensions & Organization Catalog Policy](specs/f25-plugins-extensions-organization-catalog-policy.md), and [Plan 08 — LumiAgents integration, migration, adoption](implementation/plan08-lumiagents-migration-adoption.md).
