# NIP-59 GiftWrap Transport

Technical specification for `src/nip59.rs`, the module that wraps and
unwraps Mostro messages for transport over Nostr using NIP-59
(GiftWrap).

## Goals

- Centralize the wrap / unwrap pipeline so clients do not reimplement
  NIP-59 glue.
- Honor the Mostro key-management split: long-lived **identity key**
  signs the seal; per-order **trade key** authors the rumor and
  produces the inner tuple signature.
- Preserve NIP-59 metadata hygiene: CSPRNG-based timestamp jitter,
  ephemeral outer signer, optional expiration, optional PoW.
- Keep a strict error contract that distinguishes "not addressed to
  me" from "protocol violation".

## Non-goals

The module deliberately does **not** manage relays, subscriptions,
waiters, deduplication, persistence or retries. It returns an `Event`
ready to publish and a decoder for incoming events — the caller owns
transport policy.

## Key split

Mostro derives keys per
[NIP-06](https://github.com/nostr-protocol/nips/blob/master/06.md) at
`m/44'/1237'/38383'/0/i`:

- `i = 0` → **identity key**. Stable per user; signs the seal (kind
  13) and drives the NIP-44 encryption of the seal content so the
  receiver can decrypt via `(receiver_secret, seal.pubkey)`. Sending
  the identity key to a Mostro node is what lets the node attach
  reputation to orders.
- `i ≥ 1` → **trade key**. Rotated per order; authors the rumor
  (kind 1) and produces the Schnorr signature carried in the inner
  tuple.

**Full-privacy mode** — a client that does not want reputation simply
reuses its trade key as the identity (pass the same `Keys` as both
`identity_keys` and `trade_keys`). `seal.pubkey` then coincides with
`rumor.pubkey` and no stable identity leaks to the node.

## Message pipeline

```text
Message
  │
  ▼
JSON( (Message, Option<Signature>) )          ← inner tuple
  │                         │
  │                         └── signature over message JSON, produced
  │                             with trade_keys (present when
  │                             WrapOptions.signed == true)
  ▼
Rumor (UnsignedEvent, kind 1, author = trade_keys)
  │
  ▼
Seal  (kind 13, signed by identity_keys,
       content = NIP-44(rumor) under identity_keys ↔ receiver)
  │
  ▼
GiftWrap (kind 1059, signed by fresh ephemeral keys,
          content = NIP-44(seal),
          tags = [ ["p", receiver], optional ["expiration", ts] ],
          optional PoW, randomized created_at)
```

`nostr-sdk` 0.44's `nip59::extract_rumor` enforces
`seal.pubkey == rumor.pubkey` and rejects the split above with
`SenderMismatch`. `unwrap_message` therefore performs its own NIP-44
decryption and seal-signature verification instead of calling
`extract_rumor`.

## Public API

### `WrapOptions`

```rust
pub struct WrapOptions {
    pub pow: u8,                          // NIP-13 difficulty, outer layer only
    pub expiration: Option<Timestamp>,    // NIP-40 tag on the GiftWrap
    pub signed: bool,                     // inner tuple signature on/off
}
```

`Default` yields `pow = 0`, `expiration = None`, `signed = true`.
Traffic to a Mostro node always uses `signed = true`; the unsigned
variant exists for flows where the caller intentionally forgoes
identity binding.

### `UnwrappedMessage`

```rust
pub struct UnwrappedMessage {
    pub message: Message,              // decoded Mostro payload
    pub signature: Option<Signature>,  // Some iff sender set signed = true
    pub sender: PublicKey,             // rumor author (trade key)
    pub identity: PublicKey,           // seal signer (identity key)
    pub created_at: Timestamp,         // rumor created_at (not the wrap's)
}
```

`sender` is the rumor author — the per-order trade pubkey, also the
pubkey that produced the inner tuple signature. `identity` is the
seal signer, i.e. the long-lived pubkey the sender uses to accrue
reputation. In full-privacy mode `identity == sender`.

### `wrap_message`

```rust
pub async fn wrap_message(
    message: &Message,
    identity_keys: &Keys,
    trade_keys: &Keys,
    receiver: PublicKey,
    opts: WrapOptions,
) -> Result<Event, MostroError>
```

Builds a publishable GiftWrap event. Steps:

1. Serialize `message` to JSON.
2. If `opts.signed`, sign the JSON with `trade_keys` and include the
   signature in the inner tuple; else include `None`.
3. Build the rumor as `EventBuilder::text_note(inner_json)` authored
   by `trade_keys.public_key()`. **No PoW is mined on the rumor** —
   it is encrypted inside the seal and never published alone.
4. Seal via `EventBuilder::seal(identity_keys, &receiver, rumor)`
   (NIP-44 encrypts the rumor JSON under `identity_keys ↔ receiver`)
   and sign the resulting event with `identity_keys`. Encryption and
   signing must use the same key so the receiver can derive the
   shared secret from `seal.pubkey` alone.
5. Encrypt the seal JSON with NIP-44 under a fresh ephemeral key for
   `receiver`, attach `["p", receiver]` (mandatory) and optionally
   `["expiration", ts]`, stamp `created_at =
   Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK)` (OsRng,
   0..172_800 s in the past), mine PoW at `opts.pow`, sign with the
   ephemeral key.

For full-privacy mode, pass the same `Keys` as both `identity_keys`
and `trade_keys`.

### `unwrap_message`

```rust
pub async fn unwrap_message(
    event: &Event,
    receiver_keys: &Keys,
) -> Result<Option<UnwrappedMessage>, MostroError>
```

Implementation bypasses `nip59::extract_rumor` to accommodate the
identity/trade key split. Steps:

1. Reject events whose kind is not `GiftWrap`.
2. `nip44::decrypt(receiver_secret, event.pubkey, event.content)` —
   failure here is the "not addressed to me" signal and returns
   `Ok(None)`.
3. Parse the decrypted payload as an `Event`, reject if its kind is
   not `Seal`, verify its Schnorr signature.
4. `nip44::decrypt(receiver_secret, seal.pubkey, seal.content)` to
   recover the rumor JSON. `seal.pubkey` is the identity key used on
   both sides of the outer seal encryption.
5. Parse the decrypted payload as an `UnsignedEvent`, reject if its
   kind is not `TextNote`.
6. `serde_json::from_str` the rumor content into
   `(Message, Option<String>)`.
7. When a signature string is present, parse it, verify it against
   `rumor.pubkey` (the trade key), and populate
   `UnwrappedMessage.signature`.

Contract:

- `Ok(Some(_))` on successful unwrap **and** (when `signed`)
  successful signature verification.
- `Ok(None)` **only** when the outer NIP-44 layer cannot be decrypted
  with `receiver_keys`. This is the canonical "not addressed to me"
  signal — callers can iterate across multiple candidate receiver
  keys and treat `None` as "try the next one".
- `Err(MostroInternalErr(_))` for every other failure: wrong event
  kind, corrupted seal JSON, wrong seal kind, invalid seal signature,
  inner NIP-44 decrypt failure, malformed rumor JSON, wrong rumor
  kind, malformed inner tuple JSON, malformed signature hex,
  signature that does not verify against `sender`.

### `validate_response`

```rust
pub fn validate_response(
    message: &Message,
    expected_request_id: Option<u64>,
) -> Result<(), MostroError>
```

Post-unwrap validator for responses from a Mostro node.

- Returns `Err(MostroCantDo(reason))` when the payload is `CantDo`
  (defaults to `CantDoReason::InvalidAction` when the reason is
  absent).
- When `expected_request_id` is provided, enforces that the inner
  message's `request_id` matches, unless the action is on the
  unsolicited-push allow-list (`BuyerTookOrder`,
  `HoldInvoicePayment*`, `WaitingSellerToPay`, `WaitingBuyerInvoice`,
  `BuyerInvoiceAccepted`, `PurchaseCompleted`, `Released`,
  `FiatSentOk`, `Canceled`, `CooperativeCancel*`,
  `DisputeInitiatedByPeer`, `Admin*`, `PaymentFailed`,
  `InvoiceUpdated`, `Rate`, `RateReceived`, `SendDm`), in which case a
  missing `request_id` is accepted.

Mismatched or unexpectedly-missing request ids surface as
`ServiceError::UnexpectedError`.

## Error routing

The unwrap path routes its own failures without dispatching on
`nip59::Error`:

| Stage                                | Cause                                       | Result               |
|--------------------------------------|---------------------------------------------|----------------------|
| outer `nip44::decrypt`               | payload not addressed to `receiver_keys`    | `Ok(None)`           |
| `Event::from_json` on seal           | corrupted seal payload                      | `Err(NostrError)`    |
| `seal.kind != Kind::Seal`            | decryptable but wrong kind                  | `Err(UnexpectedErr)` |
| `seal.verify_signature()`            | seal signature invalid                      | `Err(NostrError)`    |
| inner `nip44::decrypt` on seal       | seal content unreadable with `seal.pubkey`  | `Err(DecryptionErr)` |
| `UnsignedEvent::from_json` on rumor  | corrupted rumor payload                     | `Err(NostrError)`    |
| `rumor.kind != Kind::TextNote`       | wrong rumor kind                            | `Err(UnexpectedErr)` |
| `serde_json::from_str` on tuple      | malformed `(Message, Option<String>)` JSON  | `Err(MessageSerErr)` |
| `Signature::from_str` on tuple sig   | malformed hex signature                     | `Err(UnexpectedErr)` |
| `Message::verify_signature`          | signature does not verify vs `rumor.pubkey` | `Err(UnexpectedErr)` |

The `p` tag is **not** used as an addressing filter. NIP-44 decrypt
success is a cryptographic proof of addressing; a `p` tag is a
relay-routing hint that can be absent, spoofed, or mismatched without
affecting decrypt-ability.

## Security properties

### Trade-identity binding

When `signed = true`, the inner tuple carries a Schnorr signature
over the exact JSON bytes of `message`, produced with `trade_keys`.
`unwrap_message` parses the signature strictly and verifies it
against `rumor.pubkey` (the trade pubkey exposed as
`UnwrappedMessage.sender`).

The seal layer separately binds the exchange to the sender's
long-lived identity (`UnwrappedMessage.identity`). In the honest
client these two pubkeys relate via the NIP-06 derivation tree, but
the transport treats them as independent: a mismatched pair does not
violate the transport contract, it simply means the tuple signature
and seal signature were produced by different keys. Malformed
signatures and non-verifying signatures both surface as errors: "the
sender did not sign" and "the sender claims a signature we cannot
trust" must never look the same to the caller.

### Timestamp blur

Per NIP-59, GiftWrap `created_at` should be randomized to obscure the
real send time. The module calls
`Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK)`, which draws
a uniformly random `u64` in `0..172_800` (two days) from `OsRng` and
subtracts it from the current Unix second. The `Timestamp::tweaked`
helper is also what `nostr-sdk`'s own `make_seal` uses, so wrap and
seal metadata share the same distribution.

### PoW scope

`WrapOptions.pow` applies only to the outer GiftWrap event. The
rumor is encrypted inside the seal and never published on its own,
so mining its event id is pure CPU waste. The seal itself is not
mined; `nostr-sdk` does not expose a PoW hook on `EventBuilder::seal`
and the seal's id is not observable on relays in any meaningful way.

### Ephemeral outer signer

Every call to `wrap_message` generates a fresh
`Keys::generate()` for the GiftWrap signer. There is no reuse
across wraps, no persistence, and no correlation between trade
identity and the key visible on the wire.

## Usage

### Sending a request to a Mostro node

```rust
use mostro_core::prelude::*;

let wrapped = wrap_message(
    &message,                // Message with an explicit request_id
    &identity_keys,          // long-lived identity keys (index 0)
    &trade_keys,             // per-order trade keys (index ≥ 1)
    mostro_pubkey,           // PublicKey of the Mostro node
    WrapOptions::default(),  // signed = true, pow = 0, no expiration
)
.await?;

// Caller publishes `wrapped` to its relay pool.
```

For full-privacy mode (no reputation), pass the trade keys as both
arguments:

```rust
let wrapped = wrap_message(
    &message, &trade_keys, &trade_keys,
    mostro_pubkey, WrapOptions::default(),
).await?;
```

### Handling incoming events across multiple candidate receiver keys

```rust
async fn try_unwrap(event: &Event, candidates: &[Keys]) -> Option<UnwrappedMessage> {
    for keys in candidates {
        match unwrap_message(event, keys).await {
            Ok(Some(msg)) => return Some(msg),   // addressed to this key
            Ok(None) => continue,                // not this key, try the next
            Err(_e) => {
                // genuine protocol error — log, drop, or escalate
                return None;
            }
        }
    }
    None
}
```

`Ok(None)` is cheap to iterate on; `Err(_)` is rare and worth
surfacing in logs or metrics.

### Validating a response

```rust
let unwrapped = unwrap_message(&event, &receiver_keys).await?
    .ok_or_else(/* not addressed to us */)?;

validate_response(&unwrapped.message, Some(request_id))?;

// Re-verify the tuple signature (binds message to trade key):
if let Some(sig) = unwrapped.signature {
    let json = unwrapped.message.as_json()?;
    assert!(Message::verify_signature(json, unwrapped.sender, sig));
}

// unwrapped.identity is the sender's stable reputation key.
```

## Dependency surface

- `nostr-sdk = "0.44.1"` with features `nip44`, `nip59`.
- `serde_json` for the inner tuple.
- No new direct RNG dependency; randomness flows through
  `nostr-sdk`'s `Timestamp::tweaked` (OsRng).

## Testing

`src/nip59.rs` carries the behavioral tests that lock in the
contract:

- `wrap_then_unwrap_roundtrip` — dual-key round trip; asserts
  `sender == trade_keys.public_key()` and
  `identity == identity_keys.public_key()`.
- `full_privacy_mode_identity_equals_sender` — same `Keys` passed for
  both identity and trade; `identity == sender`.
- `signature_is_verifiable_with_trade_pubkey`
- `unsigned_wrap_has_no_signature`
- `expiration_tag_is_set_when_provided`
- `unwrap_with_wrong_receiver_keys_returns_none` — outer decrypt
  failure path.
- `unwrap_with_corrupted_seal_returns_err` — decryptable but
  semantically invalid seal payload.
- `unwrap_with_malformed_signature_errors` — `Some("not-a-hex-sig")`
  in the tuple must not silently become `None`.
- `unwrap_with_signature_for_other_content_errors` — well-formed sig
  that does not verify against the declared sender must error.
- `validate_response_*` suite covering `CantDo`, request-id match /
  mismatch, and the unsolicited-action allow-list.
