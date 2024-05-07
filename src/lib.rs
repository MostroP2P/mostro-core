pub mod dispute;
pub mod message;
pub mod order;
pub mod rating;
pub mod user;

/// All messages broadcasted by Mostro daemon are Parameterized Replaceable Events
/// and the event kind must be between 30000 and 39999
pub const NOSTR_REPLACEABLE_EVENT_KIND: u64 = 38383;
pub const PROTOCOL_VER: u8 = 1;

#[cfg(test)]
mod test {
    use crate::message::{Action, Content, Message, MessageKind};
    use crate::order::{Kind, SmallOrder, Status};
    use uuid::uuid;
    #[test]
    fn test_status_string() {
        assert_eq!(Status::Active.to_string(), "active");
        assert_eq!(Status::CompletedByAdmin.to_string(), "completed-by-admin");
        assert_eq!(Status::FiatSent.to_string(), "fiat-sent");
        assert_ne!(Status::Pending.to_string(), "Pending");
    }

    #[test]
    fn test_kind_string() {
        assert_ne!(Kind::Sell.to_string(), "active");
        assert_eq!(Kind::Sell.to_string(), "sell");
        assert_eq!(Kind::Buy.to_string(), "buy");
        assert_ne!(Kind::Buy.to_string(), "active");
    }

    #[test]
    fn test_order_message() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            None,
            Action::NewOrder,
            Some(Content::Order(SmallOrder::new(
                Some(uuid),
                Some(Kind::Sell),
                Some(Status::Pending),
                100,
                "eur".to_string(),
                100,
                "SEPA".to_string(),
                1,
                None,
                None,
                None,
                Some(1627371434),
                None,
            ))),
        ));
        let sample_message = r#"{"order":{"version":1,"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","pubkey":null,"action":"new-order","content":{"order":{"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","kind":"sell","status":"pending","amount":100,"fiat_code":"eur","fiat_amount":100,"payment_method":"SEPA","premium":1,"created_at":1627371434}}}}"#;
        let message = Message::from_json(sample_message).unwrap();
        assert!(message.verify());
        let message_json = message.as_json().unwrap();
        let test_message_json = test_message.as_json().unwrap();
        assert_eq!(message_json, test_message_json);
    }

    #[test]
    fn test_payment_request_content_message() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            None,
            Action::PayInvoice,
            Some(Content::PaymentRequest(
                Some(SmallOrder::new(
                    Some(uuid),
                    Some(Kind::Sell),
                    Some(Status::WaitingPayment),
                    100,
                    "eur".to_string(),
                    100,
                    "SEPA".to_string(),
                    1,
                    None,
                    None,
                    None,
                    Some(1627371434),
                    None,
                )),
                "lnbcrt78510n1pj59wmepp50677g8tffdqa2p8882y0x6newny5vtz0hjuyngdwv226nanv4uzsdqqcqzzsxqyz5vqsp5skn973360gp4yhlpmefwvul5hs58lkkl3u3ujvt57elmp4zugp4q9qyyssqw4nzlr72w28k4waycf27qvgzc9sp79sqlw83j56txltz4va44j7jda23ydcujj9y5k6k0rn5ms84w8wmcmcyk5g3mhpqepf7envhdccp72nz6e".to_string(),
            )),
        ));
        let sample_message = r#"{"order":{"version":1,"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","pubkey":null,"action":"pay-invoice","content":{"payment_request":[{"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","kind":"sell","status":"waiting-payment","amount":100,"fiat_code":"eur","fiat_amount":100,"payment_method":"SEPA","premium":1,"created_at":1627371434},"lnbcrt78510n1pj59wmepp50677g8tffdqa2p8882y0x6newny5vtz0hjuyngdwv226nanv4uzsdqqcqzzsxqyz5vqsp5skn973360gp4yhlpmefwvul5hs58lkkl3u3ujvt57elmp4zugp4q9qyyssqw4nzlr72w28k4waycf27qvgzc9sp79sqlw83j56txltz4va44j7jda23ydcujj9y5k6k0rn5ms84w8wmcmcyk5g3mhpqepf7envhdccp72nz6e"]}}}"#;
        let message = Message::from_json(sample_message).unwrap();
        assert!(message.verify());
        let message_json = message.as_json().unwrap();
        let test_message_json = test_message.as_json().unwrap();
        assert_eq!(message_json, test_message_json);
    }
}
