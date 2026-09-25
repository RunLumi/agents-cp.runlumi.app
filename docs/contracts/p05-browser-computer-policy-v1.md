# P05 browser and computer policy protocol v1

- Contract version: `p05-browser-computer-v1`
- Authority: P05-CG `p05-cg-v1`
- Execution owner: desktop/runtime host

The control plane returns a versioned, non-secret policy document. The runtime evaluates it before each sensitive action and sends only bounded decision metadata to the broker.

## Browser policy

Fields: allowed domains, blocked domains, download/upload, authenticated browsing, clipboard, and external submit (`deny|allow|require_approval`).

## Computer policy

Fields: accessibility, screen capture, keyboard/mouse, shell escalation, and allowed applications.

## Rules

- Policy version/expiry is checked before use; stale or malformed policy fails closed.
- Prompt/model output cannot enable a denied capability.
- A per-use approval is bound to the exact tool ID/fingerprint, target summary, and run.
- Actual browser/computer execution remains on the desktop/runtime host; the Worker does not take over the desktop.
