# F25 — Plugins, Extensions & Organization Catalog Policy

Priority: P1  
Depends on: F04, F11, F13

## Objective

Quản lý plugin/extension ecosystem của Lumi Agents theo organization policy, tận dụng ZCode plugin concepts nhưng không cho installed code tự động trở thành trusted code.

## Concepts

- PluginPackage
- PluginVersion
- PluginInstall
- PluginPublisher
- PluginPermissionManifest
- PluginPolicy
- PluginReviewState

## Requirements

### FR-F25-001 — Stable package identity

Plugin identity is separate from display name and version.

### FR-F25-002 — Manifest

Each version declares:

- runtime compatibility;
- tools/MCP servers exposed;
- network destinations;
- filesystem/process permissions;
- secrets requested;
- browser/computer-use capabilities;
- external data handling where known.

### FR-F25-003 — Version review

A new version that expands requested permissions MUST require renewed org/admin approval in managed mode.

### FR-F25-004 — Organization policy

Org can:

- allow official-only;
- allow approved publisher list;
- allow explicit packages;
- block package/version;
- pin versions;
- control auto-update.

### FR-F25-005 — Integrity

Installation verifies package integrity/signature/checksum through trusted distribution metadata.

### FR-F25-006 — Secret binding

Plugin requests logical secret handles by declared integration purpose; plugin does not browse all org credentials.

### FR-F25-007 — Tool registration

Tools are registered using stable plugin + version + tool identity.

Unknown/new tools default deny according to F13.

### FR-F25-008 — Revocation

Platform/org can quarantine vulnerable plugin version.

Existing sessions may finish only if security policy allows; new executions deny.

### FR-F25-009 — Audit

Install/update/approve/block actions are audited.

## ZCode compatibility

ZCode already distinguishes builtin/plugin/custom MCP sources and has a separate plugin repository. Preserve those source semantics and add centralized org governance above them.

## Web UX

- installed plugins;
- available/approved catalog;
- permissions diff on update;
- version pin;
- blocked reason;
- usage/recent executions.

## Acceptance criteria

- Plugin update cannot silently gain network/secret/tool capability.
- Blocked version cannot execute for managed org even if still present on disk.
