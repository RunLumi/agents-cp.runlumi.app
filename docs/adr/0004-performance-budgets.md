# ADR 0004: Performance budgets are architecture constraints

- Status: Accepted
- Date: 2026-09-24

"Fast" without numbers becomes decoration.

## Web

Initial route targets:

- JS <= 170 KiB gzip;
- CSS <= 35 KiB gzip;
- new route chunk <= 80 KiB gzip unless feature complexity objectively requires more;
- LCP < 2.5 s p75, target < 2.0 s authenticated shell;
- INP < 200 ms p75;
- CLS < 0.1.

## API

For requests not blocked on a third party:

- simple Worker handler compute < 10 ms p95;
- normal control-plane request < 200 ms p95 near the serving region.

Upstream-provider time must be measured separately and bounded by timeouts.

## Developer loop

Representative modern laptop:

- Vite cold start target < 1.5 s;
- typical HMR target < 200 ms;
- lint/format should feel effectively immediate for a normal diff.

## Guardrails

- no application barrel files;
- minimize Vite plugins;
- no convenience dependency without a size/maintenance case;
- lazy-load editors, charts, syntax highlighting, and other heavy features;
- paginate/virtualize unbounded data;
- avoid global provider fan-out;
- inspect browser and Worker bundle deltas after dependency changes.

## Automation

As representative product routes emerge, CI should add production asset-size reporting, stable Web Vitals/Lighthouse smoke thresholds, Worker dry-run size reporting, and endpoint benchmarks.

If a budget changes, document why and define the next threshold explicitly.
