pub mod dispute;
pub mod message;
pub mod order;
pub mod rating;
pub mod user;

/// All messages broadcasted by Mostro daemon are Parameterized Replaceable Events
/// and use 30078 as event kind
pub const NOSTR_REPLACEABLE_EVENT_KIND: u64 = 38383;
pub const PROTOCOL_VER: u8 = 1;

#[cfg(test)]
mod test {

    use crate::message::{Action, Content, Message, MessageKind};
    use crate::order::{Kind, SmallOrder, Status};
    use uuid::uuid;

    #[test]
    fn test_message_order() {
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
            ))),
        ));
        let sample_message = r#"{"Order":{"version":1,"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","pubkey":null,"action":"NewOrder","content":{"Order":{"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","kind":"Sell","status":"Pending","amount":100,"fiat_code":"eur","fiat_amount":100,"payment_method":"SEPA","premium":1,"created_at":1627371434}}}}"#;
        let message = Message::from_json(sample_message).unwrap();
        assert!(message.verify());
        let message_json = message.as_json().unwrap();
        let test_message_json = test_message.as_json().unwrap();
        assert_eq!(message_json, test_message_json);
    }
}
