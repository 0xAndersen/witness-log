# RFC-0003: DNS TXT self-registration of witnesses

Status: Draft
Target: a `registry/dns_register.py` bot and a `--dns` check in `registry/validate.py`, 0.5.x; no spec change
Related: `registry/README.md`, `GOVERNANCE.md` "Founding operators", RFC-0001 (fleet log origins)

## Motivation

Registering a witness today is a pull request that adds one JSON file,
validated by `registry/validate.py` (shape, `https://` URL, live
cross-check of `pubkey_hex` and `directory_entry.operator_org` against
`GET /`) and merged by a maintainer. Two problems with that, both about
who has to act:

1. **The operator waits on review.** The whole point of an outside
   operator is that the project does not control them; making their
   registration depend on the project's review queue is the wrong
   dependency direction, and a slow merge is a reason to not bother.
2. **The label is asserted, not demonstrated.** `operator_org` is whatever
   the PR says. The live check proves the URL serves the key, not that the
   organisation named owns the URL. A registry entry claiming "Example
   University" that points at a VM anyone could rent is the one thing the
   check cannot see (`registry/README.md`: "Mislabelling is the one
   thing the protocol cannot detect").

DNS gives both: a TXT record under a domain can only be published by
whoever controls the domain, and a bot can read it without a human in the
loop. This is the same move ACME uses for domain validation and that
several package ecosystems use for publisher verification.

## Design

### The record

The operator publishes one TXT record at `_witness-log.<domain>`:

```
_witness-log.example.org.  TXT  "v=wl1; vkey=example.org/witness+2a1af9ae+BFQKStzQLZ1Z4Eb5knwQ8kPTg24z/mdvKrWLxrsQvV4A; url=https://witness.example.org; org=Example Org; compute=hetzner; runtime=human"
```

Fields, `;`-separated, order free, unknown fields ignored:

| field | required | meaning |
|---|---|---|
| `v` | yes | `wl1` |
| `vkey` | yes | the C2SP verifier key `witness init` prints (name, key ID, base64 of type byte + public key); the key name's host part MUST be `<domain>` or a subdomain of it |
| `url` | yes | the public base URL; `https://` only; its host MUST be `<domain>` or a subdomain of it |
| `org` | yes | the `operator_org` label, byte for byte as the witness serves it |
| `compute` | no | `compute_provider` |
| `runtime` | no | `human` (default) or `agent` |

One record per witness; several witnesses under one domain are several
strings in the TXT RRset or records under `_witness-log.<label>.<domain>`.

### The bot

`registry/dns_register.py <domain>` (run by a scheduled workflow over a
list of domains that have asked once, and on `workflow_dispatch` for a new
one):

1. Resolve the TXT record over DNS-over-HTTPS from **two** independent
   resolvers (e.g. Cloudflare and Google); both answers must agree. Record
   the DNSSEC `AD` flag if either resolver sets it; it is reported, not
   required.
2. Parse; derive the entry: `name` from the vkey's key name, `pubkey` from
   its base64 (type byte MUST be `0x01` or `0x04`), `url`, `operator_org`,
   `compute_provider`, `runtime`, `is_project_operated: false`.
3. Run the existing live check: `GET <url>/` must serve the same
   `pubkey_hex` and the same `directory_entry.operator_org`. Use
   `--require-live`: an unreachable witness is not registered.
4. If the derived entry differs from `registry/witnesses/<slug>.json` (or
   the file does not exist), open a pull request that adds or updates it,
   with the resolver answers and the `GET /` body in the description, and
   label it `dns-verified`.
5. Merge policy is `GOVERNANCE.md`'s: a `dns-verified` PR that passes CI
   may be merged by the bot after a 24-hour objection window, because the
   facts it asserts were demonstrated, not claimed. A PR without the label
   (a hand-written entry) keeps today's human review.

### What `validate.py` adds

`validate.py --dns` resolves `_witness-log.<host of url>` for every entry
and, if a record exists, requires it to agree with the file (vkey,
`org`, `url`). An entry whose domain publishes no record is unchanged
(not every operator will do this); an entry whose domain publishes a
*different* record is an error, because the domain owner has said
otherwise.

### What the bot does not do

- It does not decide that "Example Org" is a real organisation or that
  the domain belongs to it. It proves that whoever controls
  `example.org`'s DNS also controls the key and the URL, and chose that
  label. A verifier building a directory still decides which domains to
  trust; the registry is a list, not an endorsement (`registry/README.md`).
- It does not remove entries. Retirement (RRset removed, witness down for
  N days on the status page) opens a PR proposing removal; a human merges.

## Wire changes

None. Nothing in `spec/SPEC.md` changes; the registry file format
(`registry/README.md`) is unchanged; the TXT record is a registry-process
artefact. The verifier does not read DNS.

## Corpus vectors needed

None for the wire format. The bot gets its own fixtures under
`registry/tests/`: a TXT string per field combination, two-resolver
agreement and disagreement, a vkey whose host is not under the domain,
a record whose `org` differs from `GET /`.

## Backward compatibility

Existing entries stay valid with no record published. `validate.py`
without `--dns` behaves as today. CI runs `--offline` as today; the
scheduled bot is the only thing that resolves names.

## Open questions

1. Should `org` be required to equal the domain's organisation name in
   some registry (WHOIS, a corporate registry)? No: that is unverifiable
   mechanically and WHOIS is mostly redacted. The domain *is* the
   demonstrated fact; the label is what the domain owner wants to be
   called. Objections welcome.
2. Two resolvers over DoH is a cheap defence against a poisoned resolver,
   not against a compromised registrar account. Is requiring DNSSEC worth
   the adoption cost? The proposal says report it, do not require it, and
   revisit once there are enough operators to measure.
3. Auto-merge after 24 hours puts a bot in the merge path. The alternative
   is "a maintainer merges within 72 hours or explains why", which is a
   promise rather than a mechanism. The proposal prefers the mechanism and
   asks whether a founding operator should hold the review key instead.
4. Agent-operated witnesses (`runtime=agent`) may not have a domain. They
   can use a subdomain the organisation delegates to them, which also
   answers "which organisation is responsible for this agent"; the RFC
   proposes no other path.
5. The same record could carry a fleet log vkey (RFC-0001) as
   `fleet=<vkey>`, so one TXT record identifies everything an organisation
   publishes to the network. Left out of this draft until RFC-0001 settles.

## How to comment

Open a thread in GitHub Discussions titled `RFC-0003` (or comment on the
pull request that added this file). Operators who would publish a record
are asked specifically whether the field set and the 24-hour window are
acceptable.
