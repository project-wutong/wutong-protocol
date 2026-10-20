# Wutong Improvement Proposals (WIP)

Normative changes to `wutong/0.1` follow the WIP process (WTP-000 §17): open a WIP issue using the
template, then a PR adding `wip/WIP-NNNN-<slug>.md`. A WIP is **Accepted** only with schema diff,
positive/negative fixtures and passing evidence from at least two independent implementations
(currently Python reference + Rust `wutong-core`). Signed bytes, permission semantics and ID
interpretation of a stable profile are never changed in place.
