//! Error taxonomy used across the crate.
//!
//! Errors surfaced to clients are modelled as [`MostroError`], which is split
//! into two branches:
//!
//! * [`MostroError::MostroCantDo`] — a "soft" error: the request was
//!   well-formed but the server refuses to perform the action (e.g. the order
//!   is not in the right state). Clients should surface the inner
//!   [`CantDoReason`] to the user.
//! * [`MostroError::MostroInternalErr`] — a "hard" error: something went
//!   wrong while processing the request (database failure, Nostr relay
//!   issue, malformed invoice, etc.). The inner [`ServiceError`] carries the
//!   diagnostic detail.
//!
//! Both inner enums implement [`Display`](std::fmt::Display) with
//! human-readable messages suited for logging.

use crate::prelude::*;

/// Machine-readable reasons carried by a `CantDo` response.
///
/// Serialized in `snake_case` so clients can pattern-match on the value
/// transported in [`crate::message::Payload::CantDo`].
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CantDoReason {
    /// The provided signature is invalid or missing.
    InvalidSignature,
    /// The specified trade index does not exist or is invalid.
    InvalidTradeIndex,
    /// The provided amount is invalid or out of acceptable range.
    InvalidAmount,
    /// The provided invoice is malformed or expired.
    InvalidInvoice,
    /// The payment request is invalid or cannot be processed.
    InvalidPaymentRequest,
    /// The specified peer is invalid or not found.
    InvalidPeer,
    /// The rating value is invalid or out of range.
    InvalidRating,
    /// The text message is invalid or contains prohibited content.
    InvalidTextMessage,
    /// The order kind is invalid.
    InvalidOrderKind,
    /// The order status is invalid.
    InvalidOrderStatus,
    /// The provided public key is invalid.
    InvalidPubkey,
    /// One or more request parameters are invalid.
    InvalidParameters,
    /// The targeted order has already been canceled.
    OrderAlreadyCanceled,
    /// User creation failed on the server side.
    CantCreateUser,
    /// The caller tried to operate on an order that does not belong to them.
    IsNotYourOrder,
    /// The requested action is not allowed in the order's current status.
    NotAllowedByStatus,
    /// The fiat amount is outside the allowed range for this order.
    OutOfRangeFiatAmount,
    /// The sats amount is outside the allowed range for this order.
    OutOfRangeSatsAmount,
    /// The caller tried to operate on a dispute that does not belong to them.
    IsNotYourDispute,
    /// A solver is being notified that an admin has taken over their dispute.
    DisputeTakenByAdmin,
    /// The caller is authenticated but lacks the permission for this action.
    NotAuthorized,
    /// A dispute could not be created (e.g. order not in a disputable state).
    DisputeCreationError,
    /// Generic "resource not found" error.
    NotFound,
    /// The dispute is in an invalid state for the requested action.
    InvalidDisputeStatus,
    /// The requested action is invalid.
    InvalidAction,
    /// The caller already has a pending order and cannot create another.
    PendingOrderExists,
    /// The fiat currency code is not accepted by this Mostro node.
    InvalidFiatCurrency,
    /// The caller is being rate-limited.
    TooManyRequests,
}

/// Internal errors raised by services behind the Mostro API.
///
/// Unlike [`CantDoReason`], values of this enum are not expected to be
/// forwarded verbatim to end users; they are meant for logs, telemetry and
/// other server-to-server diagnostics.
#[derive(Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// Wraps an error returned by `nostr_sdk`.
    NostrError(String),
    /// The invoice string could not be parsed as a valid BOLT-11 invoice.
    ParsingInvoiceError,
    /// A numeric value could not be parsed.
    ParsingNumberError,
    /// The invoice has expired.
    InvoiceExpiredError,
    /// The invoice is otherwise invalid.
    InvoiceInvalidError,
    /// The invoice expiration time is below the minimum required.
    MinExpirationTimeError,
    /// The invoice amount is below the minimum allowed.
    MinAmountError,
    /// The invoice amount does not match the expected value.
    WrongAmountError,
    /// The price API did not answer in time.
    NoAPIResponse,
    /// The requested currency is not listed by the exchange API.
    NoCurrency,
    /// The exchange API returned a response that could not be parsed.
    MalformedAPIRes,
    /// Amount value is negative where only positives are allowed.
    NegativeAmount,
    /// A Lightning Address could not be parsed.
    LnAddressParseError,
    /// A Lightning Address payment was attempted with a wrong amount.
    LnAddressWrongAmount,
    /// A Lightning payment failed; the inner string carries the reason.
    LnPaymentError(String),
    /// Communication with the Lightning node failed.
    LnNodeError(String),
    /// Order id was not found in the database.
    InvalidOrderId,
    /// Database access failed; the inner string carries the detail.
    DbAccessError(String),
    /// The provided public key is invalid.
    InvalidPubkey,
    /// Hold-invoice operation failed; the inner string carries the detail.
    HoldInvoiceError(String),
    /// Could not update the order status in the database.
    UpdateOrderStatusError,
    /// The order status is invalid.
    InvalidOrderStatus,
    /// The order kind is invalid.
    InvalidOrderKind,
    /// A dispute already exists for this order.
    DisputeAlreadyExists,
    /// Could not publish the dispute Nostr event.
    DisputeEventError,
    /// The rating message itself is invalid.
    InvalidRating,
    /// The rating value is outside the accepted range.
    InvalidRatingValue,
    /// Failed to serialize or deserialize a [`crate::message::Message`].
    MessageSerializationError,
    /// The dispute id is invalid or unknown.
    InvalidDisputeId,
    /// The dispute status is invalid.
    InvalidDisputeStatus,
    /// The payload does not match the action.
    InvalidPayload,
    /// Any other unexpected error; inner string carries the detail.
    UnexpectedError(String),
    /// An environment variable could not be read or parsed.
    EnvVarError(String),
    /// Underlying I/O error.
    IOError(String),
    /// NIP-44/NIP-59 encryption failed.
    EncryptionError(String),
    /// NIP-44/NIP-59 decryption failed.
    DecryptionError(String),
}

/// Top-level error type returned by the Mostro API surface.
///
/// Most public functions in this crate return `Result<T, MostroError>`.
/// Match on the variants to distinguish between user-actionable "can't do"
/// responses and internal service errors.
#[derive(Debug, PartialEq, Eq)]
pub enum MostroError {
    /// An internal service-level error; diagnostic only.
    MostroInternalErr(ServiceError),
    /// A structured "can't do" response to surface to the user.
    MostroCantDo(CantDoReason),
}

impl std::error::Error for MostroError {}

impl std::fmt::Display for MostroError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MostroError::MostroInternalErr(m) => write!(f, "Error caused by {}", m),
            MostroError::MostroCantDo(m) => write!(f, "Sending cantDo message to user for {:?}", m),
        }
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::ParsingInvoiceError => write!(f, "Incorrect invoice"),
            ServiceError::ParsingNumberError => write!(f, "Error parsing the number"),
            ServiceError::InvoiceExpiredError => write!(f, "Invoice has expired"),
            ServiceError::MinExpirationTimeError => write!(f, "Minimal expiration time on invoice"),
            ServiceError::InvoiceInvalidError => write!(f, "Invoice is invalid"),
            ServiceError::MinAmountError => write!(f, "Minimal payment amount"),
            ServiceError::WrongAmountError => write!(f, "The amount on this invoice is wrong"),
            ServiceError::NoAPIResponse => write!(f, "Price API not answered - retry"),
            ServiceError::NoCurrency => write!(f, "Currency requested is not present in the exchange list, please specify a fixed rate"),
            ServiceError::MalformedAPIRes => write!(f, "Malformed answer from exchange quoting request"),
            ServiceError::NegativeAmount => write!(f, "Negative amount is not valid"),
            ServiceError::LnAddressWrongAmount => write!(f, "Ln address need amount of 0 sats - please check your order"),
            ServiceError::LnAddressParseError  => write!(f, "Ln address parsing error - please check your address"),
            ServiceError::LnPaymentError(e) => write!(f, "Lightning payment failure cause: {}",e),
            ServiceError::LnNodeError(e) => write!(f, "Lightning node connection failure caused by: {}",e),
            ServiceError::InvalidOrderId => write!(f, "Order id not present in database"),
            ServiceError::InvalidPubkey => write!(f, "Invalid pubkey"),
            ServiceError::DbAccessError(e) => write!(f, "Error in database access: {}",e),
            ServiceError::HoldInvoiceError(e) => write!(f, "Error holding invoice: {}",e),
            ServiceError::UpdateOrderStatusError => write!(f, "Error updating order status"),
            ServiceError::InvalidOrderStatus => write!(f, "Invalid order status"),
            ServiceError::InvalidOrderKind => write!(f, "Invalid order kind"),
            ServiceError::DisputeAlreadyExists => write!(f, "Dispute already exists"),
            ServiceError::DisputeEventError => write!(f, "Error publishing dispute event"),
            ServiceError::NostrError(e) => write!(f, "Error in nostr: {}",e),
            ServiceError::InvalidRating => write!(f, "Invalid rating message"),
            ServiceError::InvalidRatingValue => write!(f, "Invalid rating value"),
            ServiceError::MessageSerializationError => write!(f, "Error serializing message"),
            ServiceError::InvalidDisputeId => write!(f, "Invalid dispute id"),
            ServiceError::InvalidDisputeStatus => write!(f, "Invalid dispute status"),
            ServiceError::InvalidPayload => write!(f, "Invalid payload"),
            ServiceError::UnexpectedError(e) => write!(f, "Unexpected error: {}", e),
            ServiceError::EnvVarError(e) => write!(f, "Environment variable error: {}", e),
            ServiceError::IOError(e) => write!(f, "IO error: {}", e),
            ServiceError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            ServiceError::DecryptionError(e) => write!(f, "Decryption error: {}", e),
        }
    }
}
