# Follow-up enterprise review — 0.12.0

Reviewed `d9e88310e5df53dd4f1a54221b678265970e7f5d` (0.11.0) on 7 September 2026. This review closes the concrete gaps below. Production acceptance still requires the organization's tenant access, representative evidence, identity provider, durable storage and operational ownership.

| Omission or defect | Implemented change | Acceptance evidence |
| --- | --- | --- |
| A stopped partial rolling window could be abandoned when the next invocation extended its end time | Persist the pending end before acquisition; resume the original cursor; advance and clear the pending window only after publication | Moving end, backup/restore/resume, shrinking end rejection and completed replay regressions |
| Concurrent processes could race during schema inspection and migration | One immediate transaction covers schema checks and changes; incomplete migrations roll back | Four concurrent migration workers against an old schema |
| Existing partial windows were not recoverable automatically during upgrade | Adopt one matching legacy window by source, parser, case, output and boundaries; reject ambiguous candidates | Legacy-column migration and cursor-preservation regression |
| Health could miss an expected source that never started | Offline configuration fingerprints, an expected-source inventory, missing-source issues and a Prometheus count | Never-started source detection without SDK credentials or API calls |
| Continuous collection lacked a reusable deployment example and clock-relative end | `--end now`, configurable settling delay and constrained systemd service/timer templates | Settling-boundary regression; deployment remains an explicit operator action |
| AI recovery required external SQLite scripts | Read-only usage accounting and pinned SQLite snapshot/restore commands preserving every reservation, response and cache row | WAL snapshot, pending/failed reservation retention, cache reuse without calls and corruption rejection |
| Malformed provider usage could be coerced into a smaller integer charge | Require nonnegative integer usage fields before replacing the reservation | Invalid usage retains the original reservation |
| Repository and cluster control-plane evidence was absent from named source coverage | GitHub organization audit collector/parser and Kubernetes v1 audit parser through existing CloudWatch/Splunk or offline inputs | Pagination, hostile links, exact time boundaries, audit stages, impersonation distinction and validated OCSF export |
| Analyst examples did not cover developer infrastructure incidents | Ninth executable notebook, new fixtures/configurations, updated truth labels and coverage/runbooks | Offline notebook and parser/OCSF regression gates |

## Decisions and boundaries

The release has **19 collector types and 27 parser contracts**. Existing parser versions and event IDs remain unchanged. The two new parsers start at 1.0.0. OCSF mappings advance to `ocsf-export-1.2.0`; retained 1.0.0 and 1.1.0 exports still verify. Evidence and state are never rewritten to make a failed integrity check pass.

All new collection, inventory, recovery and notebook-default operations consume zero model tokens. The existing optional task routes, one-call dispatch, explicit AI opt-in, compact evidence groups and durable case budget remain in force. A restored ledger does not authorize another attempt at an uncertain request.

These changes do not establish universal enterprise coverage. Native disk/memory/packet acquisition, additional vendor-specific APIs and long-term object-store readers require separate contracts and representative source data. Kubernetes has no historical audit listing API: its parser consumes records from the configured audit backend. See [developer incident coverage](DEVELOPER_INCIDENTS.md).

The remaining production actions are listed in [enterprise acceptance ownership](ENTERPRISE_READINESS.md). Branch protection needs a repository administrator and a second reviewer. Real OIDC flows, tenant API visibility, Tines/Databricks permissions, retention/immutability, encryption and recovery objectives must be accepted in the target environment. Repository fixtures cannot supply that evidence. No production service, collector schedule or paid model invocation is activated by installing this release.
