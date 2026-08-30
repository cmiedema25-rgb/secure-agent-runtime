# Design Decisions

## DD-001: Zero mandatory runtime dependencies

Decision: use the Python standard library for the HTTP API, provider client,
configuration, cryptography primitives, and test suite.

Reason: the repository can be cloned and verified offline, and its
security-relevant behavior is directly inspectable. This also minimizes
dependency confusion and transitive package risk.

Tradeoff: the included server intentionally has fewer features than a mature
web framework. Production deployment should place it behind a hardened reverse
proxy or adapt the same runtime to an established application stack.

## DD-002: Deterministic policy has final authority

Decision: a model may propose an action but cannot authorize it.

Reason: natural-language model behavior is probabilistic and cannot serve as a
reliable access-control boundary.

Tradeoff: fixed policy creates false positives and requires explicit changes
when new tools are introduced.

## DD-003: Review is a stop state

Decision: review never means execute now and inspect later.

Reason: a review decision indicates insufficient confidence for autonomous
execution. The caller can implement an approval workflow, but this runtime does
not silently downgrade review to allow.

## DD-004: Do not retain raw prompts in audit records

Decision: store a SHA-256 payload digest and redacted decision metadata.

Reason: full prompts frequently contain private data. A digest supports
correlation without turning the audit file into a second sensitive-data store.

Tradeoff: investigators need access to separately governed source data to
reconstruct the exact prompt.

## DD-005: HMAC rather than an unkeyed hash

Decision: authenticate each record with HMAC-SHA-256 and link it to the prior
record hash.

Reason: anyone who can edit a file can recompute an unkeyed hash chain. HMAC
requires the separate signing key.

Tradeoff: key compromise allows an attacker to rewrite the chain. Key
protection and remote checkpoints remain deployment responsibilities.

## DD-006: Curated evaluation results are labeled narrowly

Decision: retain exact results while stating that the dataset is self-contained
and not independently certified.

Reason: evidence should be reproducible without turning a regression score into
an unsupported security claim.
