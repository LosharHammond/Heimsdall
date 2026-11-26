# Policies

A policy is a schema-validated JSON document (`schema_version: 1`) stored as immutable, numbered versions. Editing a
policy creates a new version (only if the document actually changed). Every decision records the version used.
The engine is pure and deterministic ([`src/shared/policy.ts`](../src/shared/policy.ts)); **no language model is involved in any decision.**

```json
{
  "schema_version": 1,
  "description": "optional",
  "budget": { "max_allowed_actions": 200, "window_seconds": 3600 },
  "rules": [
    {
      "id": "read-docs",
      "description": "optional, shown in explanations",
      "effect": "allow",
      "match": {
        "tools": ["documents"],
        "operations": ["read"],
        "resources": ["docs/**"],
        "destination_domains": ["partner.example.com", "*.files.example.com"],
        "data_classifications": ["public", "internal"]
      },
      "approval": { "required_role": "admin", "ttl_seconds": 900 }
    }
  ]
}
```

`effect` is `allow`, `deny` or `require_approval` (`approval` is only valid on the latter; `required_role` is `admin` or `owner`).
Operations: `read, create, update, delete, external_transfer, command_execution`. Classifications: `public, internal, confidential, restricted`.

## Matching

- A rule matches when **every** constraint it lists matches; omitted constraints match anything (except where validation forbids it, below).
- `tools`: exact lowercase name or `*`. `operations`: exact.
- `resources`: namespace globs on the *normalized* resource. `*` = within one path segment, `**` = across segments. `docs/**` matches `docs/a/b.txt`.
  Resources containing `..`, a leading `/`, control characters or encoded separators (`%2e`, `%2f`, `%5c`) are denied as `INVALID_RESOURCE`.
- `destination_domains`: exact (`partner.example.com`) or subdomain wildcard (`*.files.example.com`, which does **not** match `files.example.com` itself).
  The destination is normalized first (URL parser, lowercase, IDNA/punycode, trailing dot removed). Credentials in a URL, non-http(s) schemes
  and malformed values are denied as `INVALID_DESTINATION`. IP literals (including decimal/hex forms) never match a domain list, and private
  hostnames (`localhost`, `*.local`, `*.internal`) and bare TLD wildcards cannot be written into a policy.
- `data_classifications`: matches the **self-declared** classification on the request (the platform cannot verify it).

## Precedence (documented and tested)

1. **Invalid identity or revoked credential/agent -> deny** (checked before any policy; `CREDENTIAL_INVALID`, `CREDENTIAL_REVOKED`, `AGENT_REVOKED`).
2. **Explicit `deny` rules override everything else**, regardless of order.
3. **`require_approval` rules** -> `require_approval` until a valid action-specific approval exists, then `allow` (`APPROVAL_GRANTED`). They are evaluated *before* allow rules, so an allow rule cannot bypass an approval requirement.
4. **Explicit `allow` rules** permit matching actions.
5. **Anything unmatched is denied** (`NO_MATCHING_RULE`, or the more specific `DESTINATION_NOT_APPROVED` when a rule matched everything except the destination). An agent with no policy assigned is denied (`NO_POLICY_ASSIGNED`).

### Exceptions to the order (all deliberate)

- **Budget** (`budget`): after steps 3-4, if the agent already has `max_allowed_actions` allowed decisions (plus consumed approvals) inside the window, the result becomes `deny` / `BUDGET_EXCEEDED`. This can turn an allow into a deny; it never turns a deny into an allow.
- **Fail-closed classification**: a `deny` or `require_approval` rule that lists `data_classifications` also matches requests that declare **no** classification. An `allow` rule with `data_classifications` does not. (So the example "no restricted data leaves" rule also denies undeclared transfers; declare a classification.)
- **Validation guards**: `allow` rules must list `tools` and `operations`; allowing `external_transfer` requires `destination_domains`. There is no "allow everything" rule.
- **Monitor mode**: when an agent is in monitor mode the response decision is `allow` with `MONITOR_ONLY`; the real outcome is stored as `policy_decision` and shown as advisory. Identity and revocation checks still apply.
- **Execution-time recheck**: at claim time the policy is evaluated again against the *current* version. An action allowed earlier is refused if a deny rule now applies. An approval is void if the policy version or the agent's policy assignment changed after approval.

## Approvals

A `require_approval` decision creates a pending approval bound to: organization, agent, action digest (tool, operation, resource, destination, classification, full args), policy version and required role.
A human with at least that role approves or rejects; the requesting key has no route to do so. After approval the action may be claimed **once** within 5 minutes
(`APPROVAL_GRANT_SEC`). Requests not decided within `ttl_seconds` expire. See [API](API.md#post-v1actionsrequestidclaim-scope-actions) for the refusal codes.

## Example policies (also in [`examples/policies/`](../examples/policies))

| File | Behaviour |
| --- | --- |
| `read-only-assistant.json` | May read `docs/**`; everything else denied by default |
| `summarizer.json` | Reads `docs/**`, creates `summaries/**`, **never** deletes (explicit deny) |
| `approved-destinations.json` | External transfer only to `partner.example.com` / `*.files.example.com`; restricted data never leaves |
| `destructive-needs-approval.json` | Reads and updates allowed; deletes need administrator approval of that exact action |
| `no-commands.json` | Command execution explicitly denied, plus a 200-actions/hour budget |
| `demo-workspace.json` | The policy used by `npm run demo` |

Use **Policies -> Try it** in the dashboard to dry-run an action against a document without recording anything.
