pub mod dispute;
pub mod message;
pub mod order;
pub mod rating;
pub mod user;

/// All messages broadcasted by Mostro daemon are Parameterized Replaceable Events
/// and use 30078 as event kind
pub const NOSTR_REPLACEABLE_EVENT_KIND: u64 = 30078;


#[cfg(test)]
mod test {

    use crate::message::{Action, Content, Message, MessageKind};
    use crate::order::{Kind, NewOrder, Status};
    use uuid::Uuid;

    #[test]
    fn test_message_order() {
        let uuid = Uuid::new_v4();
        let test = Message::Order(MessageKind::new(
            0,
            Some(uuid),
            None,
            Action::NewOrder,
            Some(Content::Order(NewOrder::new(
                Some(uuid),
                Kind::Sell,
                Status::Pending,
                100,
                "eur".to_string(),
                100,
                "SEPA".to_string(),
                1,
                None,
                None,
                None,
                1627371434,
            ))),
        ));

        if let Some(ord) = test.get_order() {
            println!("{:?}", ord);
        }
    }
}