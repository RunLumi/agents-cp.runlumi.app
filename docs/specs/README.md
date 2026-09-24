# Lumi Agents Control Plane — Feature Specifications

Status: living product/engineering contract  
Scope: backend + web control plane for the Lumi Agents fork of ZCode  
Date baseline: 2026-09-24

## Mục tiêu

Thư mục này định nghĩa **toàn bộ feature surface cần thiết** để biến Lumi Agents từ một desktop-first ZCode fork thành một hệ thống có organization account, policy, usage, inference routing, audit, device enrollment và enterprise-ready control plane.

Mỗi feature nằm trong một file riêng, đánh số `f01`, `f02`, ... để coding agents có thể triển khai theo thứ tự, tham chiếu ổn định và không làm mất dependency giữa các phần.

## Nguyên tắc

1. **Backend là authority** cho identity, org membership, authorization, entitlements, budgets, audit và cloud-managed policy.
2. **Lumi Agents desktop/CLI vẫn là execution surface**, đặc biệt với workspace local, files, shell, browser use và computer use.
3. **Không phá local-first/BYOK hiện có của ZCode.** Control plane phải hỗ trợ coexistence và migration dần.
4. **Tenant isolation là invariant**, không phải feature tùy chọn.
5. **Secrets không bao giờ được gửi xuống client nếu client không thực sự cần chúng.**
6. **AI inference router/proxy phải vendor-neutral ở contract**, dù deployment hiện tại chạy trên Cloudflare Workers.
7. **MVP tránh enterprise theater.** SSO/SCIM/custom roles/billing nâng cao có phase riêng nhưng schema không được khóa đường nâng cấp.
8. Mỗi mutation quan trọng phải có audit trail; mỗi hành động agent có side effect phải truy được principal, org, device, session/run và policy decision.

## Priority

- **P0 / MVP:** cần để nhiều organization dùng an toàn.
- **P1 / Production:** cần trước khi scale usage thực.
- **P2 / Enterprise:** chỉ làm khi customer demand xuất hiện hoặc feature khác phụ thuộc.

## Feature index

| ID | Feature | Priority |
|---|---|---|
| F01 | Identity & Authentication | P0 |
| F02 | Organization & Tenant Lifecycle | P0 |
| F03 | Membership, Invitations & Teams | P0 |
| F04 | Authorization & Policy Engine | P0 |
| F05 | Sessions, Devices & Account Security | P0 |
| F06 | Domains, SSO & SCIM | P2 |
| F07 | Projects, Workspaces & Resource Ownership | P0 |
| F08 | Agents, Sessions, Runs, Conversations & Artifacts | P0 |
| F09 | Model & Provider Catalog | P0 |
| F10 | AI Inference Router / Proxy | P0 |
| F11 | Credentials, Secrets & BYOK | P0 |
| F12 | Usage Metering, Quotas, Budgets & Cost Controls | P0 |
| F13 | Tools, MCP, Browser & Computer Use Policies | P0 |
| F14 | API Keys, Service Accounts & Machine Identity | P1 |
| F15 | Automations, Scheduled & Off-peak Tasks | P1 |
| F16 | Audit Logs, Security Events & Support Access | P0 |
| F17 | Notifications, Webhooks & Event Delivery | P1 |
| F18 | Billing, Plans, Entitlements & Licensing | P1 |
| F19 | Device Enrollment & Policy Sync | P0 |
| F20 | Data Governance, Export, Retention & Deletion | P1 |
| F21 | Operations, Observability & Reliability | P0 |
| F22 | Web Control Plane UX & Information Architecture | P0 |
| F23 | API Contracts, Versioning, Pagination & Idempotency | P0 |
| F24 | Admin/Support, Abuse Controls & Feature Rollouts | P1 |
| F25 | Plugins, Extensions & Organization Catalog Policy | P1 |
| F26 | Migration from Local ZCode State to Org-aware Lumi Agents | P0 |

## Cross-cutting security invariants

Mọi protected operation MUST establish:

```text
principal
+ authenticated session or machine identity
+ active organization context
+ active membership
+ permission decision
+ resource scope/ownership
+ entitlement/budget/policy constraints where applicable
```

Biết một `resource_id` không bao giờ đồng nghĩa có quyền truy cập.

## Cross-cutting UX invariants

- Org switch phải rõ ràng và không để stale org context.
- Loading / empty / error / permission-denied / destructive states phải được thiết kế, không để fallback browser text.
- Keyboard navigation và visible focus là bắt buộc.
- Không hiển thị secret đầy đủ sau khi lưu.
- Mọi hành động irreversible phải mô tả consequence trước khi confirm.

## Evidence from ZCode

Current ZCode contains real concepts that these specs intentionally map onto:

- workspace/session/task protocol;
- model/provider registry and account-provider access;
- coding-plan entitlements and usage views;
- custom/official MCP;
- browser use and computer use;
- remote workspace/session infrastructure;
- automation/cron/off-peak task scheduling;
- local SQLite task/session persistence.

The control plane should extend these concepts instead of inventing a parallel vocabulary.

## Implementation rule

Before implementing a feature, read:

1. this index;
2. the feature spec;
3. relevant files in `docs/adr/`;
4. current LumiAgents/ZCode integration points.

If code needs to violate a MUST requirement, update the spec/ADR first rather than silently drifting.
