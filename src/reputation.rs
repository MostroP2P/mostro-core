//! Reputation attestations (kind `38388`).
//!
//! An attestation is a Nostr event an *issuer* (a Mostro instance or
//! lnp2pBot) signs to state the reputation a user earned there, addressed to
//! one identity on a destination instance that will import it. It is never
//! published to relays: it travels inside the `reputation-exported` reply and
//! the `import-reputation` request. A rebind authorisation shares the kind and
//! moves the issuer's binding of a source account to a new identity.
//!
//! This module builds both events and parses them, applying every rule the
//! event itself carries: signature, kind, document tag, tag formats and the
//! clock. What depends on the receiver — whether the issuer is trusted, whether
//! it is the receiver's own key, whether the attestation names the identity
//! the transport proved, whether the rebind is signed by the bound identity —
//! stays with the caller.
//!
//! The rules are those of the protocol's
//! [reputation attestation](https://mostro.network/protocol/reputation_attestation.html)
//! chapter, and the tests run its test vectors.

use std::collections::HashMap;
use std::fmt;

use nostr_sdk::prelude::*;

use crate::error::CantDoReason;
use crate::prelude::NOSTR_REPUTATION_ATTESTATION_KIND;

/// Lifetime an issuer gives an attestation, and the default cap a
/// destination enforces: 7 days.
pub const ATTESTATION_LIFETIME_SECS: u64 = 7 * SECONDS_PER_DAY;
/// Clock skew tolerated on both `created_at` and `expiration`.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Longest a rebind authorisation may live.
pub const REBIND_MAX_LIFETIME_SECS: u64 = 3_600;
/// Fewest ratings received an attestation can carry: the eligibility floor.
pub const MIN_ATTESTED_REVIEWS: u32 = 5;
/// Earliest first-trade date an attestation can carry: 2020-01-01, before
/// any issuer existed.
pub const MIN_ATTESTED_SINCE: u64 = 1_577_836_800;
/// Lowest and highest `rating` an attestation can carry, in hundredths.
const RATING_RANGE: std::ops::RangeInclusive<u16> = 100..=500;
const SUBJECT_MAX_LEN: usize = 64;
const SECONDS_PER_DAY: u64 = 86_400;
const ATTESTATION_DOCUMENT: &str = "reputation-attestation";
const REBIND_DOCUMENT: &str = "reputation-rebind";

/// Why an attestation or a rebind authorisation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The text is not a Nostr event.
    Malformed,
    /// The event id does not match its content, or the signature is invalid.
    InvalidSignature,
    /// The event is not of kind `38388`.
    WrongKind,
    /// The `z` tag is missing or names another document.
    WrongDocument,
    /// A required tag is absent.
    MissingTag(&'static str),
    /// A tag that must appear once appears more than once.
    RepeatedTag(&'static str),
    /// A tag value breaks its format or range.
    InvalidTag(&'static str),
    /// `created_at` is later than the clock allows.
    NotYetValid,
    /// `expiration` has passed.
    Expired,
    /// `expiration - created_at` exceeds the allowed lifetime.
    LifetimeTooLong,
    /// An argument passed to a builder would produce an event that does not
    /// parse.
    InvalidInput(&'static str),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "not a Nostr event"),
            Self::InvalidSignature => write!(f, "invalid event id or signature"),
            Self::WrongKind => write!(f, "not a kind {NOSTR_REPUTATION_ATTESTATION_KIND} event"),
            Self::WrongDocument => write!(f, "missing or unexpected z tag"),
            Self::MissingTag(t) => write!(f, "missing `{t}` tag"),
            Self::RepeatedTag(t) => write!(f, "repeated `{t}` tag"),
            Self::InvalidTag(t) => write!(f, "invalid `{t}` tag"),
            Self::NotYetValid => write!(f, "created in the future"),
            Self::Expired => write!(f, "expired"),
            Self::LifetimeTooLong => write!(f, "lifetime exceeds the allowed maximum"),
            Self::InvalidInput(what) => write!(f, "invalid {what}"),
        }
    }
}

impl std::error::Error for AttestationError {}

impl AttestationError {
    /// The `cant-do` reason a destination answers an attestation refused
    /// with this error: `expired_reputation_attestation` when it expired,
    /// `invalid_reputation_attestation` otherwise. A refused rebind
    /// authorisation is always [`CantDoReason::InvalidReputationRebind`].
    pub fn cant_do_reason(&self) -> CantDoReason {
        match self {
            Self::Expired => CantDoReason::ExpiredReputationAttestation,
            _ => CantDoReason::InvalidReputationAttestation,
        }
    }
}

/// A parsed, verified reputation attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationAttestation {
    /// Event id, which identifies the attestation.
    pub id: EventId,
    /// Key the issuer signed with.
    pub issuer: PublicKey,
    /// Identity the attestation is addressed to (`p`).
    pub destination: PublicKey,
    /// The source account, opaque and stable within the issuer.
    pub subject: String,
    /// Ratings received on the source.
    pub reviews: u32,
    /// Average of those ratings, in hundredths (`487` is `4.87`).
    pub rating_hundredths: u16,
    /// First completed trade on the source, a UTC day start.
    pub since: u64,
    /// When the issuer signed it.
    pub created_at: u64,
    /// When it stops being redeemable.
    pub expiration: u64,
}

impl ReputationAttestation {
    /// Average rating as a number, `4.87` for `rating_hundredths == 487`.
    ///
    /// The division is correctly rounded, so this is the same double as
    /// parsing the decimal string the event carries.
    pub fn rating(&self) -> f64 {
        f64::from(self.rating_hundredths) / 100.0
    }

    /// Average rating as the event writes it, with two decimals.
    pub fn rating_text(&self) -> String {
        format_rating(self.rating_hundredths)
    }

    /// Sign an attestation with the issuer's dedicated key.
    ///
    /// `average` is the issuer's internal average; it is rounded and clamped
    /// as [`rating_hundredths`] does. The arguments are checked against the
    /// rules a destination applies, so a successful build always parses.
    /// `lifetime` is at most [`ATTESTATION_LIFETIME_SECS`], the default cap.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        issuer: &Keys,
        destination: &PublicKey,
        subject: &str,
        reviews: u32,
        average: f64,
        since: u64,
        created_at: Timestamp,
        lifetime: u64,
    ) -> Result<Event, AttestationError> {
        let created = created_at.as_secs();
        if !valid_subject(subject) {
            return Err(AttestationError::InvalidInput("subject"));
        }
        if reviews < MIN_ATTESTED_REVIEWS {
            return Err(AttestationError::InvalidInput("reviews"));
        }
        let hundredths =
            rating_hundredths(average).ok_or(AttestationError::InvalidInput("average"))?;
        if !valid_since(since, created) {
            return Err(AttestationError::InvalidInput("since"));
        }
        if lifetime == 0 || lifetime > ATTESTATION_LIFETIME_SECS {
            return Err(AttestationError::InvalidInput("lifetime"));
        }
        let expiration = created
            .checked_add(lifetime)
            .ok_or(AttestationError::InvalidInput("lifetime"))?;
        let tags = [
            Tag::public_key(*destination),
            custom_tag("subject", subject),
            custom_tag("reviews", &reviews.to_string()),
            custom_tag("rating", &format_rating(hundredths)),
            custom_tag("since", &since.to_string()),
            custom_tag("expiration", &expiration.to_string()),
            custom_tag("z", ATTESTATION_DOCUMENT),
        ];
        sign(issuer, tags, created_at)
    }

    /// Parse and verify an attestation event.
    ///
    /// Applies every rule of the event: id and signature, kind, `z`, each tag
    /// exactly once and in range, `created_at` no later than `now` plus the
    /// skew, `expiration` no earlier than `now` minus the skew, and a lifetime
    /// of at most `max_lifetime` seconds. The trust list, the receiver's own
    /// issuer key and the identity match are the caller's.
    pub fn parse(
        event: &Event,
        now: Timestamp,
        max_lifetime: u64,
    ) -> Result<Self, AttestationError> {
        verify(event, ATTESTATION_DOCUMENT)?;
        let tags = single_tags(
            event,
            &["p", "subject", "reviews", "rating", "since", "expiration"],
        )?;
        let destination = hex_key(tags["p"], "p")?;
        let subject = tags["subject"];
        if !valid_subject(subject) {
            return Err(AttestationError::InvalidTag("subject"));
        }
        let reviews = decimal(tags["reviews"])
            .and_then(|r| u32::try_from(r).ok())
            .filter(|r| *r >= MIN_ATTESTED_REVIEWS)
            .ok_or(AttestationError::InvalidTag("reviews"))?;
        let rating_hundredths =
            parse_rating(tags["rating"]).ok_or(AttestationError::InvalidTag("rating"))?;
        let created_at = event.created_at.as_secs();
        let since = decimal(tags["since"])
            .filter(|s| valid_since(*s, created_at))
            .ok_or(AttestationError::InvalidTag("since"))?;
        let expiration = decimal(tags["expiration"])
            .filter(|e| *e > created_at)
            .ok_or(AttestationError::InvalidTag("expiration"))?;
        check_clock(created_at, expiration, now, max_lifetime)?;
        Ok(Self {
            id: event.id,
            issuer: event.pubkey,
            destination,
            subject: subject.to_string(),
            reviews,
            rating_hundredths,
            since,
            created_at,
            expiration,
        })
    }

    /// [`ReputationAttestation::parse`] on the JSON serialisation an
    /// attestation travels in. Returns the event too, so a caller can keep
    /// exactly what it received.
    pub fn parse_json(
        json: &str,
        now: Timestamp,
        max_lifetime: u64,
    ) -> Result<(Self, Event), AttestationError> {
        let event = Event::from_json(json).map_err(|_| AttestationError::Malformed)?;
        Self::parse(&event, now, max_lifetime).map(|a| (a, event))
    }
}

/// What a destination keeps of an import to be able to reverse it: the
/// three figures it merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationImport {
    /// Ratings received the import added.
    pub reviews: u32,
    /// Their average, in hundredths.
    pub rating_hundredths: u16,
    /// The first-trade date it carried.
    pub since: u64,
}

impl ReputationImport {
    /// Average rating as a number, the same double the merge used.
    pub fn rating(&self) -> f64 {
        f64::from(self.rating_hundredths) / 100.0
    }
}

impl From<&ReputationAttestation> for ReputationImport {
    fn from(a: &ReputationAttestation) -> Self {
        Self {
            reviews: a.reviews,
            rating_hundredths: a.rating_hundredths,
            since: a.since,
        }
    }
}

/// A parsed, verified rebind authorisation: the identity a source account is
/// bound to at an issuer consents to moving the binding to a new identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationRebind {
    /// Event id.
    pub id: EventId,
    /// The identity that signed it, which must be the one currently bound.
    pub bound_identity: PublicKey,
    /// The identity the binding moves to (`p`).
    pub new_identity: PublicKey,
    /// The issuer key it is valid at (`issuer`).
    pub issuer: PublicKey,
    /// When it was signed.
    pub created_at: u64,
    /// When it stops being valid.
    pub expiration: u64,
}

impl ReputationRebind {
    /// Sign a rebind authorisation with the currently bound identity.
    ///
    /// `lifetime` is at most [`REBIND_MAX_LIFETIME_SECS`].
    pub fn build(
        bound_identity: &Keys,
        issuer: &PublicKey,
        new_identity: &PublicKey,
        created_at: Timestamp,
        lifetime: u64,
    ) -> Result<Event, AttestationError> {
        if lifetime == 0 || lifetime > REBIND_MAX_LIFETIME_SECS {
            return Err(AttestationError::InvalidInput("lifetime"));
        }
        let expiration = created_at.as_secs() + lifetime;
        let tags = [
            Tag::public_key(*new_identity),
            custom_tag("issuer", &issuer.to_hex()),
            custom_tag("expiration", &expiration.to_string()),
            custom_tag("z", REBIND_DOCUMENT),
        ];
        sign(bound_identity, tags, created_at)
    }

    /// Parse and verify a rebind authorisation.
    ///
    /// Whether the signer is the identity actually bound, whether `issuer`
    /// is the receiver's own issuer key, and whether `p` is the destination
    /// of the export request it travels in, is the caller's to check.
    pub fn parse(event: &Event, now: Timestamp) -> Result<Self, AttestationError> {
        verify(event, REBIND_DOCUMENT)?;
        let tags = single_tags(event, &["p", "issuer", "expiration"])?;
        let new_identity = hex_key(tags["p"], "p")?;
        let issuer = hex_key(tags["issuer"], "issuer")?;
        let created_at = event.created_at.as_secs();
        let expiration = decimal(tags["expiration"])
            .filter(|e| *e > created_at)
            .ok_or(AttestationError::InvalidTag("expiration"))?;
        check_clock(created_at, expiration, now, REBIND_MAX_LIFETIME_SECS)?;
        Ok(Self {
            id: event.id,
            bound_identity: event.pubkey,
            new_identity,
            issuer,
            created_at,
            expiration,
        })
    }

    /// [`ReputationRebind::parse`] on a JSON serialisation.
    pub fn parse_json(json: &str, now: Timestamp) -> Result<Self, AttestationError> {
        let event = Event::from_json(json).map_err(|_| AttestationError::Malformed)?;
        Self::parse(&event, now)
    }
}

/// The `rating` an issuer writes for an internal average, in hundredths:
/// `clamp(round(average × 100), 100, 500)` in double precision, rounding half
/// away from zero. `None` for a non-finite average.
///
/// Rounding the double, not a decimal string, is what keeps implementations
/// in agreement: `4.895 × 100` is `489.49999999999994`, so `4.895` gives
/// `4.89`.
pub fn rating_hundredths(average: f64) -> Option<u16> {
    if !average.is_finite() {
        return None;
    }
    let (low, high) = (*RATING_RANGE.start(), *RATING_RANGE.end());
    Some(
        (average * 100.0)
            .round()
            .clamp(f64::from(low), f64::from(high)) as u16,
    )
}

/// Write a rating in hundredths with exactly two decimals.
pub fn format_rating(hundredths: u16) -> String {
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

fn custom_tag(name: &str, value: &str) -> Tag {
    Tag::custom(name, [value])
}

fn sign<const N: usize>(
    keys: &Keys,
    tags: [Tag; N],
    created_at: Timestamp,
) -> Result<Event, AttestationError> {
    EventBuilder::new(Kind::Custom(NOSTR_REPUTATION_ATTESTATION_KIND), "")
        .tags(tags)
        .custom_created_at(created_at)
        .finalize(keys)
        .map_err(|_| AttestationError::InvalidInput("signing key"))
}

/// Id, signature, kind and `z`, in that order.
fn verify(event: &Event, document: &str) -> Result<(), AttestationError> {
    event
        .verify()
        .map_err(|_| AttestationError::InvalidSignature)?;
    if event.kind != Kind::Custom(NOSTR_REPUTATION_ATTESTATION_KIND) {
        return Err(AttestationError::WrongKind);
    }
    let documents: Vec<&str> = values(event, "z").collect();
    match documents.as_slice() {
        [z] if *z == document => Ok(()),
        _ => Err(AttestationError::WrongDocument),
    }
}

/// The first value of every tag called `name`.
fn values<'a>(event: &'a Event, name: &'a str) -> impl Iterator<Item = &'a str> {
    event
        .tags
        .iter()
        .filter_map(move |tag| match tag.as_slice() {
            [kind, value, ..] if kind == name => Some(value.as_str()),
            [kind] if kind == name => Some(""),
            _ => None,
        })
}

/// The value of each named tag, which must appear exactly once.
fn single_tags<'a>(
    event: &'a Event,
    names: &[&'static str],
) -> Result<HashMap<&'static str, &'a str>, AttestationError> {
    let mut found = HashMap::new();
    for name in names {
        let mut all = values(event, name);
        let value = all.next().ok_or(AttestationError::MissingTag(name))?;
        if all.next().is_some() {
            return Err(AttestationError::RepeatedTag(name));
        }
        found.insert(*name, value);
    }
    Ok(found)
}

fn hex_key(value: &str, tag: &'static str) -> Result<PublicKey, AttestationError> {
    let lowercase_hex = value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !lowercase_hex {
        return Err(AttestationError::InvalidTag(tag));
    }
    PublicKey::from_hex(value).map_err(|_| AttestationError::InvalidTag(tag))
}

/// A base-10 integer with no sign, leading zero or whitespace.
fn decimal(value: &str) -> Option<u64> {
    let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
    let canonical = value == "0" || !value.starts_with('0');
    (digits && canonical).then(|| value.parse().ok()).flatten()
}

/// `d.dd`, between `1.00` and `5.00`.
fn parse_rating(value: &str) -> Option<u16> {
    let bytes = value.as_bytes();
    let shape = bytes.len() == 4
        && bytes[1] == b'.'
        && [bytes[0], bytes[2], bytes[3]]
            .iter()
            .all(u8::is_ascii_digit);
    if !shape {
        return None;
    }
    let digit = |i: usize| u16::from(bytes[i] - b'0');
    Some(digit(0) * 100 + digit(2) * 10 + digit(3)).filter(|h| RATING_RANGE.contains(h))
}

fn valid_subject(subject: &str) -> bool {
    (1..=SUBJECT_MAX_LEN).contains(&subject.len())
        && subject
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_since(since: u64, created_at: u64) -> bool {
    since.is_multiple_of(SECONDS_PER_DAY) && since >= MIN_ATTESTED_SINCE && since <= created_at
}

fn check_clock(
    created_at: u64,
    expiration: u64,
    now: Timestamp,
    max_lifetime: u64,
) -> Result<(), AttestationError> {
    let now = now.as_secs();
    if created_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(AttestationError::NotYetValid);
    }
    if now > expiration.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(AttestationError::Expired);
    }
    if expiration - created_at > max_lifetime {
        return Err(AttestationError::LifetimeTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../tests/vectors/reputation_v1.json");

    /// Well-formed attestations that only the destination's context refuses.
    const CONTEXT_REFUSALS: [&str; 3] = ["identity_mismatch", "untrusted_issuer", "own_issuer_key"];
    /// Well-formed rebinds that only the issuer's context refuses.
    const REBIND_CONTEXT_REFUSALS: [&str; 3] = [
        "signed_by_other_identity",
        "other_issuer",
        "other_destination",
    ];

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vectors parse")
    }

    fn event(v: &Value) -> Event {
        Event::from_json(v.to_string()).expect("vector event parses")
    }

    fn u64_at(v: &Value, key: &str) -> u64 {
        v[key].as_u64().expect("number")
    }

    fn now(v: &Value) -> Timestamp {
        Timestamp::from(u64_at(&v["context"], "now"))
    }

    fn max_lifetime(v: &Value) -> u64 {
        u64_at(&v["context"], "max_lifetime")
    }

    fn keys(v: &Value, label: &str) -> Keys {
        Keys::parse(v["secret_keys"][label].as_str().expect("key")).expect("valid key")
    }

    fn key(hex: &Value) -> PublicKey {
        PublicKey::from_hex(hex.as_str().expect("hex")).expect("valid key")
    }

    #[test]
    fn the_valid_attestation_parses_to_its_expected_fields() {
        let v = vectors();
        let valid = &v["attestation"]["valid"];
        let expect = &valid["expect"];
        let (parsed, event) = ReputationAttestation::parse_json(
            valid["json"].as_str().expect("json"),
            now(&v),
            max_lifetime(&v),
        )
        .expect("valid attestation");
        assert_eq!(event.id.to_hex(), valid["id"].as_str().expect("id"));
        assert_eq!(parsed.id, event.id);
        assert_eq!(parsed.issuer, key(&expect["issuer_key"]));
        assert_eq!(parsed.destination, key(&expect["destination"]));
        assert_eq!(parsed.subject, expect["subject"].as_str().expect("subject"));
        assert_eq!(u64::from(parsed.reviews), u64_at(expect, "reviews"));
        assert_eq!(
            parsed.rating_text(),
            expect["rating"].as_str().expect("rating")
        );
        assert_eq!(parsed.rating(), "4.87".parse::<f64>().expect("decimal"));
        assert_eq!(parsed.since, u64_at(expect, "since"));
        assert_eq!(parsed.created_at, u64_at(expect, "created_at"));
        assert_eq!(parsed.expiration, u64_at(expect, "expiration"));
    }

    #[test]
    fn every_accepted_edge_parses() {
        let v = vectors();
        for case in v["attestation"]["accepted"].as_array().expect("cases") {
            let result =
                ReputationAttestation::parse(&event(&case["event"]), now(&v), max_lifetime(&v));
            assert!(result.is_ok(), "{}: {result:?}", case["name"]);
        }
    }

    #[test]
    fn every_invalid_attestation_is_refused_by_the_event_or_left_to_the_caller() {
        let v = vectors();
        for case in v["attestation"]["invalid"].as_array().expect("cases") {
            let name = case["name"].as_str().expect("name");
            let result =
                ReputationAttestation::parse(&event(&case["event"]), now(&v), max_lifetime(&v));
            if CONTEXT_REFUSALS.contains(&name) {
                assert!(result.is_ok(), "{name} is well formed: {result:?}");
                continue;
            }
            let err = result.expect_err(name);
            let reason = serde_json::to_value(err.cant_do_reason()).expect("reason serialises");
            assert_eq!(reason, case["reason"], "{name}: {err:?}");
        }
    }

    #[test]
    fn the_context_refusals_are_caught_by_the_checks_a_destination_adds() {
        let v = vectors();
        let ctx = &v["context"];
        let identity = key(&ctx["proven_identity"]);
        let own = key(&ctx["own_issuer_key"]);
        let trusted: Vec<PublicKey> = ctx["trust_list"]
            .as_array()
            .expect("entries")
            .iter()
            .flat_map(|e| e["keys"].as_array().expect("keys").iter().map(key))
            .collect();
        for case in v["attestation"]["invalid"].as_array().expect("cases") {
            let name = case["name"].as_str().expect("name");
            if !CONTEXT_REFUSALS.contains(&name) {
                continue;
            }
            let a = ReputationAttestation::parse(&event(&case["event"]), now(&v), max_lifetime(&v))
                .expect(name);
            let refused =
                !trusted.contains(&a.issuer) || a.issuer == own || a.destination != identity;
            assert!(refused, "{name} must fail a context check");
        }
    }

    #[test]
    fn rating_rounds_half_away_from_zero_on_the_double() {
        for case in vectors()["rating_rounding"].as_array().expect("cases") {
            let average = case["average"].as_f64().expect("average");
            let hundredths = rating_hundredths(average).expect("finite");
            assert_eq!(
                format_rating(hundredths),
                case["rating"].as_str().expect("rating"),
                "{average}"
            );
        }
        assert_eq!(rating_hundredths(f64::NAN), None);
        assert_eq!(rating_hundredths(f64::INFINITY), None);
    }

    #[test]
    fn the_valid_rebind_parses_to_its_expected_fields() {
        let v = vectors();
        let rebind = &v["rebind"];
        let expect = &rebind["valid"]["expect"];
        let now = Timestamp::from(u64_at(&rebind["context"], "now"));
        let parsed =
            ReputationRebind::parse_json(rebind["valid"]["json"].as_str().expect("json"), now)
                .expect("valid rebind");
        assert_eq!(parsed.bound_identity, key(&expect["bound_identity"]));
        assert_eq!(parsed.new_identity, key(&expect["new_identity"]));
        assert_eq!(parsed.issuer, key(&expect["issuer"]));
        assert_eq!(parsed.created_at, u64_at(expect, "created_at"));
        assert_eq!(parsed.expiration, u64_at(expect, "expiration"));
    }

    #[test]
    fn every_invalid_rebind_is_refused_by_the_event_or_by_the_issuers_checks() {
        let v = vectors();
        let rebind = &v["rebind"];
        let ctx = &rebind["context"];
        let now = Timestamp::from(u64_at(ctx, "now"));
        let (bound, issuer) = (key(&ctx["bound_identity"]), key(&ctx["issuer_key"]));
        let destination = key(&ctx["destination"]);
        for case in rebind["invalid"].as_array().expect("cases") {
            let name = case["name"].as_str().expect("name");
            let result = ReputationRebind::parse(&event(&case["event"]), now);
            if REBIND_CONTEXT_REFUSALS.contains(&name) {
                let r = result.expect(name);
                assert!(
                    r.bound_identity != bound
                        || r.issuer != issuer
                        || r.new_identity != destination,
                    "{name}"
                );
            } else {
                assert!(result.is_err(), "{name}: {result:?}");
            }
        }
    }

    #[test]
    fn an_attestation_is_never_taken_for_a_rebind_or_the_reverse() {
        let v = vectors();
        let attestation = event(&v["attestation"]["valid"]["event"]);
        assert_eq!(
            ReputationRebind::parse(&attestation, now(&v)),
            Err(AttestationError::WrongDocument)
        );
        let rebind = event(&v["rebind"]["valid"]["event"]);
        let rebind_now = Timestamp::from(u64_at(&v["rebind"]["context"], "now"));
        assert_eq!(
            ReputationAttestation::parse(&rebind, rebind_now, max_lifetime(&v)),
            Err(AttestationError::WrongDocument)
        );
    }

    #[test]
    fn a_built_attestation_parses_back_to_what_was_built() {
        let v = vectors();
        let issuer = keys(&v, "issuer-a");
        let destination = keys(&v, "identity").public_key();
        let created = Timestamp::from(1_790_899_200);
        let event = ReputationAttestation::build(
            &issuer,
            &destination,
            "a-source-account",
            214,
            4.866_574_074_074_074,
            1_696_204_800,
            created,
            ATTESTATION_LIFETIME_SECS,
        )
        .expect("builds");
        let parsed = ReputationAttestation::parse(&event, created, ATTESTATION_LIFETIME_SECS)
            .expect("parses");
        assert_eq!(parsed.issuer, issuer.public_key());
        assert_eq!(parsed.destination, destination);
        assert_eq!(parsed.subject, "a-source-account");
        assert_eq!(parsed.reviews, 214);
        assert_eq!(parsed.rating_text(), "4.87");
        assert_eq!(parsed.since, 1_696_204_800);
        assert_eq!(
            parsed.expiration,
            created.as_secs() + ATTESTATION_LIFETIME_SECS
        );
    }

    #[test]
    fn a_built_rebind_parses_back_to_what_was_built() {
        let v = vectors();
        let bound = keys(&v, "identity");
        let issuer = keys(&v, "issuer-a").public_key();
        let new = keys(&v, "new-identity").public_key();
        let created = Timestamp::from(1_790_899_200);
        let event =
            ReputationRebind::build(&bound, &issuer, &new, created, REBIND_MAX_LIFETIME_SECS)
                .expect("builds");
        let parsed = ReputationRebind::parse(&event, created).expect("parses");
        assert_eq!(parsed.bound_identity, bound.public_key());
        assert_eq!((parsed.issuer, parsed.new_identity), (issuer, new));
    }

    #[test]
    fn the_builders_refuse_what_a_destination_would_refuse() {
        let issuer = Keys::generate();
        let p = Keys::generate().public_key();
        let at = Timestamp::from(1_790_899_200);
        let since = 1_696_204_800;
        let life = ATTESTATION_LIFETIME_SECS;
        let build = |subject: &str, reviews, average, since, lifetime| {
            ReputationAttestation::build(
                &issuer, &p, subject, reviews, average, since, at, lifetime,
            )
        };
        assert_eq!(
            build("", 5, 4.0, since, life),
            Err(AttestationError::InvalidInput("subject"))
        );
        assert_eq!(
            build("a b", 5, 4.0, since, life),
            Err(AttestationError::InvalidInput("subject"))
        );
        assert_eq!(
            build("s", 4, 4.0, since, life),
            Err(AttestationError::InvalidInput("reviews"))
        );
        assert_eq!(
            build("s", 5, f64::NAN, since, life),
            Err(AttestationError::InvalidInput("average"))
        );
        assert_eq!(
            build("s", 5, 4.0, since + 1, life),
            Err(AttestationError::InvalidInput("since"))
        );
        assert_eq!(
            build("s", 5, 4.0, at.as_secs() + 86_400, life),
            Err(AttestationError::InvalidInput("since"))
        );
        assert_eq!(
            build("s", 5, 4.0, since, 0),
            Err(AttestationError::InvalidInput("lifetime"))
        );
        assert_eq!(
            build("s", 5, 4.0, since, ATTESTATION_LIFETIME_SECS + 1),
            Err(AttestationError::InvalidInput("lifetime"))
        );
        assert_eq!(
            ReputationRebind::build(&issuer, &p, &p, at, REBIND_MAX_LIFETIME_SECS + 1),
            Err(AttestationError::InvalidInput("lifetime"))
        );
    }

    #[test]
    fn a_legacy_average_below_one_is_clamped_not_refused() {
        let issuer = Keys::generate();
        let at = Timestamp::from(1_790_899_200);
        let event = ReputationAttestation::build(
            &issuer,
            &Keys::generate().public_key(),
            "legacy",
            5,
            0.5,
            1_696_204_800,
            at,
            ATTESTATION_LIFETIME_SECS,
        )
        .expect("builds");
        let parsed =
            ReputationAttestation::parse(&event, at, ATTESTATION_LIFETIME_SECS).expect("parses");
        assert_eq!(parsed.rating_text(), "1.00");
    }
}
