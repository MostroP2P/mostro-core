# Security Policy

`mostro-core` is the library that defines the Mostro protocol types, the order and dispute state machines, the NIP-59 and NIP-44 transports, and the P2P chat envelope. It is a dependency of the Mostro daemon and of every Mostro client, so a defect here is inherited by all of them: a flaw in signature verification, key derivation, or envelope handling can compromise funds and user privacy across the whole network at once. Security reports are treated as a priority.

## Supported Versions

Security fixes are developed against the `main` branch and released in the next published version. Only the latest release on [crates.io](https://crates.io/crates/mostro-core) and the current `main` branch receive security updates; older releases are not patched or backported.

Because this crate is a dependency rather than a deployed application, shipping a fix here is only the first step. When a fix lands we notify the maintainers of the affected downstream repositories so they can bump the dependency and cut their own releases. Downstream projects are expected to track the latest release.

## Reporting a Vulnerability

Report suspected vulnerabilities privately by email to:

**security@mostro.network**

Do not open a public GitHub issue, pull request, or discussion for a security report, and do not post details in the public Telegram groups. Public disclosure before a fix is available exposes every Mostro node, client, and user.

If you want to encrypt your report, ask for a public key at that address before sending details.

Include as much of the following as you can:

- A description of the issue and the impact you believe it has.
- The affected version, tag, or commit hash, and the affected module (for example `nip59`, `transport`, `chat`, `message`).
- Whether the issue is reachable through the crate's public API, and under which Cargo features (`wasm`, `sqlx`).
- Step-by-step reproduction instructions, ideally as a failing test or a small example using `mostro_core::prelude`.
- Any proof-of-concept code, logs, or Nostr events that demonstrate the problem.
- Whether the issue has been disclosed or reported anywhere else.

Reports in English or Spanish are both fine.

## What to Expect

- **Acknowledgement:** within 72 hours of your report.
- **Initial assessment:** within 7 days, including our severity evaluation and whether we accept the report.
- **Status updates:** at least every 14 days while the issue remains open.
- **Resolution:** we aim to ship a fix within 90 days of triage; complex protocol-level issues may take longer, and we will tell you if that is the case.

If you do not receive an acknowledgement within 72 hours, resend your message — mail delivery failures happen.

## Coordinated Disclosure

We ask that you give us a reasonable window to develop and ship a fix before disclosing publicly. Our target is coordinated disclosure once a patched release is available and downstream projects have had a chance to upgrade, or 90 days after triage, whichever comes first.

When a fix is released we publish an advisory describing the issue, the affected versions, and the upgrade path. Reporters are credited by name or handle unless they ask to remain anonymous.

## Scope

In scope: the library in this repository, including

- Protocol message construction, serialization, and signature verification (`message`).
- Order, dispute, user, and rating types and their state transitions (`order`, `dispute`, `user`, `rating`).
- The NIP-59 GiftWrap transport, including the identity/trade key split, seal and rumor handling, and metadata hygiene (`nip59`).
- Transport selection and the NIP-44 direct `kind: 14` path, including kind-based dispatch (`transport`).
- The P2P chat envelope: HKDF derivation of `K_conv` and `K_sign`, encryption, subscription filters, and sender authorization (`chat`).
- Information disclosure through the error taxonomy (`error`).
- SQLite persistence helpers behind the `sqlx` feature (`db`), and the `wasm-bindgen` surface behind the `wasm` feature.

Out of scope for this policy:

- The Mostro daemon, its escrow and Lightning logic: report to [MostroP2P/mostro](https://github.com/MostroP2P/mostro).
- Client applications maintained in other repositories under the [MostroP2P organization](https://github.com/MostroP2P). Report those to the corresponding repository.
- Vulnerabilities in third-party dependencies such as `nostr-sdk`, `bitcoin`, `sqlx`, or the `hkdf` and `sha2` crates. Report those upstream, but tell us if `mostro-core` is exploitable through them.
- Infrastructure operated by third parties, such as public Nostr relays or Lightning nodes you do not control.
- Issues that require an already-compromised host, database, or private keys.
- Misuse of the library by a caller in a way the documented API does not permit, unless the API makes the unsafe usage the natural one.
- Social engineering, physical attacks, and volumetric denial of service against public infrastructure.

Reports about the Mostro protocol specification itself can also be sent to the same address.

## Safe Harbor

We consider security research conducted in good faith and in accordance with this policy to be authorized, and we will not pursue legal action over it. In return, we ask that you:

- Test against regtest, testnet, or an instance you operate — never against production instances or other users' trades.
- Avoid accessing, modifying, or destroying data that is not yours.
- Avoid degrading the service for other users.
- Give us a reasonable time to respond before disclosing.
