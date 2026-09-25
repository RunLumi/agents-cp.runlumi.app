# Provider/model identity mapping v1

P04-INT-02 defines a one-way compatibility boundary for existing ZCode/LumiAgents identities.

| Existing identity | Lumi identity | Behavior |
|---|---|---|
| Local provider/model ID | No managed mapping unless explicitly registered | Continue local/BYOK execution when policy permits. |
| `openai` + compatible model | Stable `Provider`/`Model` IDs chosen by the catalog | Managed clients request a Lumi alias. |
| Vendor display name or model rename | Existing stable catalog ID | Catalog migration updates the provider model ID without changing the Lumi model ID. |
| Unknown provider/model | No route | Managed inference returns `model_not_allowed`; the client does not guess a replacement. |

The mapping table is server-controlled catalog data. Provider/model strings from a client are never accepted as route authority, and local secrets are never uploaded during migration. P08 owns adoption and migration UX; P04 provides this stable vocabulary and the inference client boundary.

A managed client sends the alias only. During catalog resolution, an existing ZCode identity may be associated with a catalog `provider_id`/`model_id` by a server-side migration record, but the association is one-way and informational: changing a display name or provider model string never changes the stable Lumi IDs. The LumiAgents provider boundary exposes the same runtime-only mapping resolver; unknown associations return no alias and the gateway does not guess a replacement or use a local credential as a fallback.
