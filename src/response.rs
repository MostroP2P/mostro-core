//! Validation of the responses a client receives from a Mostro node.

use crate::message::{Action, Message, Payload};
use crate::prelude::{CantDoReason, MostroError, ServiceError};

/// Validate a response received from a Mostro node.
///
/// * Returns `Err(MostroCantDo(reason))` when the payload is `CantDo`.
/// * Returns `Err(MostroInternalErr(...))` when `expected_request_id` is
///   provided and the inner message carries a different id, or no id at all
///   on an action that requires one.
/// * Otherwise returns `Ok(())`.
///
/// The allow-list of actions that may arrive without a `request_id` (server
/// push messages such as state transitions, DMs, payment failures, etc.) is
/// intentionally kept on the caller side, because the exact set depends on
/// the client flow; this function only enforces the universal rules.
pub fn validate_response(
    message: &Message,
    expected_request_id: Option<u64>,
) -> Result<(), MostroError> {
    let inner = message.get_inner_message_kind();

    if let Some(Payload::CantDo(reason)) = &inner.payload {
        return Err(MostroError::MostroCantDo(
            reason.clone().unwrap_or(CantDoReason::InvalidAction),
        ));
    }

    if let Some(expected) = expected_request_id {
        match inner.request_id {
            Some(got) if got == expected => {}
            Some(_) => {
                return Err(MostroError::MostroInternalErr(
                    ServiceError::UnexpectedError("mismatched request_id".to_string()),
                ));
            }
            None => {
                if !action_accepts_missing_request_id(&inner.action) {
                    return Err(MostroError::MostroInternalErr(
                        ServiceError::UnexpectedError(
                            "missing request_id on a response that requires one".to_string(),
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Actions that may legitimately arrive without a `request_id` even when the
/// caller was waiting on one (unsolicited server-initiated events).
fn action_accepts_missing_request_id(action: &Action) -> bool {
    matches!(
        action,
        Action::BuyerTookOrder
            | Action::HoldInvoicePaymentAccepted
            | Action::HoldInvoicePaymentSettled
            | Action::HoldInvoicePaymentCanceled
            | Action::WaitingSellerToPay
            | Action::WaitingBuyerInvoice
            | Action::BuyerInvoiceAccepted
            | Action::PurchaseCompleted
            | Action::Released
            | Action::FiatSentOk
            | Action::Canceled
            | Action::CooperativeCancelInitiatedByPeer
            | Action::CooperativeCancelAccepted
            | Action::DisputeInitiatedByPeer
            | Action::AdminSettled
            | Action::AdminCanceled
            | Action::AdminTookDispute
            | Action::PaymentFailed
            | Action::InvoiceUpdated
            | Action::Rate
            | Action::RateReceived
            | Action::SendDm
            | Action::BondSlashed
            | Action::CashuEscrowLocked
            | Action::CashuPmSignature
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageKind;
    use uuid::uuid;

    fn sample_order_message(request_id: Option<u64>) -> Message {
        let peer = crate::message::Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            None,
        );
        Message::Order(MessageKind::new(
            Some(uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")),
            request_id,
            Some(1),
            Action::FiatSentOk,
            Some(Payload::Peer(peer)),
        ))
    }

    #[test]
    fn validate_response_cant_do_short_circuits() {
        let msg = Message::cant_do(
            Some(uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")),
            Some(5),
            Some(Payload::CantDo(Some(CantDoReason::NotAuthorized))),
        );
        let err = validate_response(&msg, Some(5)).unwrap_err();
        match err {
            MostroError::MostroCantDo(CantDoReason::NotAuthorized) => {}
            _ => panic!("expected CantDo(NotAuthorized)"),
        }
    }

    #[test]
    fn validate_response_request_id_match() {
        let msg = sample_order_message(Some(9));
        validate_response(&msg, Some(9)).unwrap();
    }

    #[test]
    fn validate_response_request_id_mismatch_errors() {
        let msg = sample_order_message(Some(9));
        let err = validate_response(&msg, Some(10)).unwrap_err();
        assert!(matches!(err, MostroError::MostroInternalErr(_)));
    }

    #[test]
    fn validate_response_allows_unsolicited_actions_without_request_id() {
        let msg = Message::Order(MessageKind::new(
            Some(uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")),
            None,
            None,
            Action::BuyerTookOrder,
            None,
        ));
        validate_response(&msg, Some(1)).unwrap();
    }

    #[test]
    fn validate_response_with_no_expected_id_is_ok() {
        let msg = sample_order_message(None);
        validate_response(&msg, None).unwrap();
    }

    #[test]
    fn validate_response_allows_cashu_server_events_without_request_id() {
        // Both Cashu notifications are server-originated and may arrive while
        // the client is still waiting on an earlier request_id.
        for action in [Action::CashuEscrowLocked, Action::CashuPmSignature] {
            let msg = Message::Order(MessageKind::new(
                Some(uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23")),
                None,
                None,
                action,
                None,
            ));
            validate_response(&msg, Some(1)).unwrap();
        }
    }
}
