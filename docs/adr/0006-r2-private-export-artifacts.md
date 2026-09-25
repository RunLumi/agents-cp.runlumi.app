# ADR 0006: Private R2 artifacts for exports

- Status: Accepted
- Date: 2026-09-25
- Scope: P06 export jobs and deletion traversal

## Context

F20 requires organization and personal exports to be asynchronous, encrypted/access-controlled, short-lived, auditable, and tenant-isolated. D1 is authoritative for job metadata but is not appropriate for large export content. Cloudflare R2 provides an object binding with strongly consistent writes/deletes and streaming reads, but public buckets and bearer presigned URLs would weaken the control plane's authorization boundary.

## Decision

Use one private R2 bucket binding for export artifacts and keep all job metadata in D1.

- The bucket is private; no public bucket, public custom domain, or permanent object URL is used.
- The Worker uses the R2 binding (`put`, `get`, `head`, `list`, `delete`) rather than constructing a public object path or calling the R2 REST API from domain code.
- D1 stores only the opaque object key, checksum/size, creation time, expiry, owning scope, and audit correlation. Raw export content never enters D1 metadata, queue payloads, logs, or events.
- Object keys are server-generated and unguessable, for example `exports/{org_id}/{export_id}/{opaque_object_id}`. Organization/user IDs are authorization metadata, not sufficient access tokens.
- R2's managed storage encryption at rest and private binding are the baseline. P06 may add application-level envelope encryption if the measured export format requires it; the decision must be recorded before changing the public artifact format.
- Export collection and packaging are asynchronous queue jobs. The download endpoint reauthorizes the current principal, job scope, state, and expiry, then streams the R2 body through the Worker. It does not return a permanent or reusable object URL.
- If a short-lived presigned URL is introduced later, it is a separate Change Request/ADR because the URL is a bearer credential. P06 uses the Worker-mediated route by default.
- R2 object deletion is idempotent and driven by the same durable export/deletion job state. A deletion job verifies object absence before completion; D1 metadata is not sufficient evidence.
- A lifecycle/backup policy must ensure expired objects disappear according to the documented retention window. Backups are handled by the platform lifecycle and are not selectively rewritten for an active deletion request.

## Consequences

Positive:

- Large export content stays out of D1 and the request path.
- Authorization is checked at download time, so an expired/revoked grant cannot rely only on a leaked object path.
- Streaming avoids unbounded `arrayBuffer()`/`text()` reads in the Worker.
- Object and metadata deletion can be audited and resumed independently.

Trade-offs:

- Export packaging requires a queue worker and R2 binding configuration.
- A Worker-mediated download consumes Worker request resources for the transfer.
- R2 lifecycle/backup behavior must be configured and tested separately from D1 migrations.
- Application-level encryption beyond R2's managed encryption is deferred until a concrete threat/model measurement requires it.

## Implementation constraints

- Do not add a public R2 bucket or `workers.dev` public URL for export artifacts.
- Do not place secrets, raw prompts, or authorization headers in R2 custom metadata.
- Use bounded metadata and stream object bodies; never call `text()`/`arrayBuffer()` on an unbounded object.
- Use a small R2 adapter; do not spread raw `Env` or R2 handles through domain modules.
- Bind the bucket and signing/encryption secrets through Wrangler configuration; never commit credentials.
- Test cross-tenant key substitution, expired grants, retry/idempotent packaging, partial deletion, and object-expiry cleanup.

## Rollback

Application rollback disables export creation/download workers while retaining the private bucket and additive D1 metadata until the documented expiry/deletion lifecycle completes. Do not drop or rewrite historical job rows as a rollback mechanism.

## References

- Cloudflare Workers R2 binding API: <https://developers.cloudflare.com/r2/api/workers/workers-api-reference/>
- Cloudflare R2 presigned URL security guidance: <https://developers.cloudflare.com/r2/api/s3/presigned-urls/>
