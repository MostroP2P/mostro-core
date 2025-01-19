use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents specific reasons why a requested action cannot be performed
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CantDoReason {
    /// The provided signature is invalid or missing
    InvalidSignature,
    /// The specified trade index does not exist or is invalid
    InvalidTradeIndex,
    /// The provided amount is invalid or out of acceptable range
    InvalidAmount,
    /// The provided invoice is malformed or expired
    InvalidInvoice,
    /// The payment request is invalid or cannot be processed
    InvalidPaymentRequest,
    /// The specified peer is invalid or not found
    InvalidPeer,
    /// The rating value is invalid or out of range
    InvalidRating,
    /// The text message is invalid or contains prohibited content
    InvalidTextMessage,
    /// The order kind is invalid
    InvalidOrderKind,
    /// The order status is invalid
    InvalidOrderStatus,
    /// Invalid pubkey
    InvalidPubkey,
    /// Invalid parameters
    InvalidParameters,
    /// The order is already canceled
    OrderAlreadyCanceled,
    /// Can't create user
    CantCreateUser,
    /// For users trying to do actions on orders that are not theirs
    IsNotYourOrder,
    /// For users trying to do actions on orders not allowed by status
    NotAllowedByStatus,
    /// Fiat amount is out of range
    OutOfRangeFiatAmount,
    /// Sats amount is out of range
    OutOfRangeSatsAmount,
    /// For users trying to do actions on dispute that are not theirs
    IsNotYourDispute,
    /// For users trying to create a dispute on an order that is not in dispute
    DisputeCreationError,
    /// Generic not found
    NotFound,
    /// Invalid dispute status
    InvalidDisputeStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServiceError {
    NostrError(String),
    ParsingInvoiceError,
    ParsingNumberError,
    InvoiceExpiredError,
    InvoiceInvalidError,
    MinExpirationTimeError,
    MinAmountError,
    WrongAmountError,
    NoAPIResponse,
    NoCurrency,
    MalformedAPIRes,
    NegativeAmount,
    LnAddressParseError,
    LnAddressWrongAmount,
    LnPaymentError(String),
    LnNodeError(String),
    InvalidOrderId,
    DbAccessError(String),
    InvalidPubkey,
    HoldInvoiceError(String),
    UpdateOrderStatusError,
    InvalidOrderStatus,
    InvalidOrderKind,
    DisputeAlreadyExists,
    DisputeEventError,
    InvalidRating,
    InvalidRatingValue,
    MessageSerializationError,
    InvalidDisputeId,
    InvalidDisputeStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MostroError {
    MostroInternalErr(ServiceError),
    MostroCantDo(CantDoReason),
}

impl std::error::Error for MostroError {}

impl fmt::Display for MostroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MostroError::MostroInternalErr(m) => write!(f, "Error caused by {}", m),
            MostroError::MostroCantDo(m) => write!(f, "Sending cantDo message to user for {:?}", m),
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        }
    }
}

// impl From<lightning_invoice::Bolt11ParseError> for MostroError {
//     fn from(_: lightning_invoice::Bolt11ParseError) -> Self {
//         MostroError::ParsingInvoiceError
//     }
// }

// impl From<lightning_invoice::ParseOrSemanticError> for MostroError {
//     fn from(_: lightning_invoice::ParseOrSemanticError) -> Self {
//         MostroError::ParsingInvoiceError
//     }
// }

// impl From<std::num::ParseIntError> for MostroError {
//     fn from(_: std::num::ParseIntError) -> Self {
//         MostroError::ParsingNumberError
//     }
// }

// impl From<reqwest::Error> for MostroError {
//     fn from(_: reqwest::Error) -> Self {
//         MostroError::NoAPIResponse
//     }
// }
