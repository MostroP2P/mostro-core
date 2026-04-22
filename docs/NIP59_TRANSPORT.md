# NIP-59 GiftWrap Transport

Technical specification for `src/nip59.rs`, the module that wraps and
unwraps Mostro messages for transport over Nostr using NIP-59
(GiftWrap).

## Goals

- Centralize the wrap / unwrap pipeline so clients do not reimplement
  NIP-59 glue.
- Cryptographically bind every message to the sender's trade identity
  via an inner tuple signature.
- Preserve NIP-59 metadata hygiene: CSPRNG-based timestamp jitter,
  ephemeral outer signer, optional expiration, optional PoW.
- Keep a strict error contract that distinguishes "not addressed to
  me" from "protocol violation".

## Non-goals

The module deliberately does **not** manage relays, subscriptions,
waiters, deduplication, persistence or retries. It returns an `Event`
ready to publish and a decoder for incoming events — the caller owns
transport policy.

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
Seal  (kind 13, signed by trade_keys, content = NIP-44(rumor))
  │
  ▼
GiftWrap (kind 1059, signed by fresh ephemeral keys,
          content = NIP-44(seal),
          tags = [ ["p", receiver], optional ["expiration", ts] ],
          optional PoW, randomized created_at)
```

`nostr-sdk` 0.44 enforces that the rumor author equals the seal signer
(`nip59::Error::SenderMismatch`). Both layers are therefore signed with
`trade_keys`; the outer GiftWrap is always signed with a freshly
generated ephemeral keypair.

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
    pub sender: PublicKey,             // rumor / seal author
    pub created_at: Timestamp,         // rumor created_at (not the wrap's)
}
```

`sender` is the trade pubkey of the sender. Because `nostr-sdk`
rejects `SenderMismatch`, `sender` is also the pubkey that signed the
seal, which is the same key that produced the inner tuple signature.

### `wrap_message`

```rust
pub async fn wrap_message(
    message: &Message,
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
4. Seal via `EventBuilder::seal(trade_keys, &receiver, rumor)` and
   sign with `trade_keys`.
5. Encrypt the seal JSON with NIP-44 under a fresh ephemeral key for
   `receiver`, attach `["p", receiver]` (mandatory) and optionally
   `["expiration", ts]`, stamp `created_at =
   Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK)` (OsRng,
   0..172_800 s in the past), mine PoW at `opts.pow`, sign with the
   ephemeral key.

### `unwrap_message`

```rust
pub async fn unwrap_message(
    event: &Event,
    trade_keys: &Keys,
) -> Result<Option<UnwrappedMessage>, MostroError>
```

Contract:

- `Ok(Some(_))` on successful unwrap **and** (when `signed`)
  successful signature verification.
- `Ok(None)` **only** when the outer NIP-44 layer cannot be decrypted
  with `trade_keys`. This is the canonical "not addressed to me"
  signal — callers can iterate across multiple candidate trade keys
  and treat `None` as "try the next one".
- `Err(MostroInternalErr(_))` for every other failure: wrong event
  kind, corrupted seal JSON, invalid seal signature, NIP-59
  `SenderMismatch`, malformed inner tuple JSON, malformed signature
  hex, signature that does not verify against `sender`.

The `Signer` / non-`Signer` split on `nip59::Error` is used to
implement this contract (see "Error routing" below).

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

`nip59::extract_rumor` (from `nostr-sdk`) returns four error variants.
`unwrap_message` routes them as follows:

| Upstream variant          | Cause                                   | Result               |
|---------------------------|-----------------------------------------|----------------------|
| `Signer(_)`               | outer NIP-44 decrypt failed             | `Ok(None)`           |
| `Event(_)`                | bad seal JSON / signature / rumor JSON  | `Err(NostrError)`    |
| `SenderMismatch`          | rumor author ≠ seal author              | `Err(NostrError)`    |
| `NotGiftWrap`             | wrong kind (pre-checked, defensive)     | `Err(NostrError)`    |

The `p` tag is **not** used as an addressing filter. NIP-44 decrypt
success is a cryptographic proof of addressing; a `p` tag is a
relay-routing hint that can be absent, spoofed, or mismatched without
affecting decrypt-ability.

## Security properties

### Trade-identity binding

When `signed = true`, the inner tuple carries a Schnorr signature
over the exact JSON bytes of `message`, produced with `trade_keys`.
`unwrap_message` parses the signature strictly and verifies it
against `unwrapped.sender` (the trade pubkey that signed the seal).

The verification is redundant with the seal signature in the
honest-client case — `nostr-sdk` already rejects seals whose author
does not match the rumor — but it defends against any future drift
where the two layers diverge, and it gives callers a single
`UnwrappedMessage.signature` they can re-verify or forward on its
own. Malformed signatures and non-verifying signatures both surface
as errors: "the sender did not sign" and "the sender claims a
signature we cannot trust" must never look the same to the caller.

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
    &trade_keys,             // per-trade keys
    mostro_pubkey,           // PublicKey of the Mostro node
    WrapOptions::default(),  // signed = true, pow = 0, no expiration
)
.await?;

// Caller publishes `wrapped` to its relay pool.
```

### Handling incoming events across multiple candidate trade keys

```rust
async fn try_unwrap(event: &Event, candidates: &[Keys]) -> Option<UnwrappedMessage> {
    for keys in candidates {
        match unwrap_message(event, keys).await {
            Ok(Some(msg)) => return Some(msg),   // addressed to this trade key
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
let unwrapped = unwrap_message(&event, &trade_keys).await?
    .ok_or_else(/* not addressed to us */)?;

validate_response(&unwrapped.message, Some(request_id))?;

// Re-verify the signature if the caller wants to forward it:
if let Some(sig) = unwrapped.signature {
    let json = unwrapped.message.as_json()?;
    assert!(Message::verify_signature(json, unwrapped.sender, sig));
}
```

## Dependency surface

- `nostr-sdk = "0.44.1"` with features `nip44`, `nip59`.
- `serde_json` for the inner tuple.
- No new direct RNG dependency; randomness flows through
  `nostr-sdk`'s `Timestamp::tweaked` (OsRng).

## Testing

`src/nip59.rs` carries the behavioral tests that lock in the
contract:

- `wrap_then_unwrap_roundtrip`
- `signature_is_verifiable_with_trade_pubkey`
- `unsigned_wrap_has_no_signature`
- `expiration_tag_is_set_when_provided`
- `unwrap_with_wrong_trade_keys_returns_none` — outer decrypt failure
  path.
- `unwrap_with_corrupted_seal_returns_err` — decryptable but
  semantically invalid seal payload.
- `unwrap_with_malformed_signature_errors` — `Some("not-a-hex-sig")`
  in the tuple must not silently become `None`.
- `unwrap_with_signature_for_other_content_errors` — well-formed sig
  that does not verify against the declared sender must error.
- `validate_response_*` suite covering `CantDo`, request-id match /
  mismatch, and the unsolicited-action allow-list.
