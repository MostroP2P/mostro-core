pub mod crypto;
pub mod dispute;
pub mod error;
pub mod message;
pub mod order;
pub mod prelude;
pub mod rating;
pub mod user;
#[cfg(test)]
mod test {
    use crate::error::CantDoReason;
    use crate::message::{Action, Message, MessageKind, Payload, Peer};
    use crate::order::{Kind, SmallOrder, Status};
    use nostr_sdk::Keys;
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
        let payment_methods = "SEPA,Bank transfer".to_string();
        let payload = Payload::Order(
            SmallOrder::new(
                Some(uuid),
                Some(Kind::Sell),
                Some(Status::Pending),
                100,
                "eur".to_string(),
                None,
                None,
                100,
                payment_methods,
                1,
                None,
                None,
                None,
                Some(1627371434),
                None,
            ),
            None,
        );

        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::NewOrder,
            Some(payload),
        ));
        let test_message_json = test_message.as_json().unwrap();
        let sample_message = r#"{"order":{"version":1,"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","request_id":1,"trade_index":2,"action":"new-order","payload":{"order":[{"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","kind":"sell","status":"pending","amount":100,"fiat_code":"eur","fiat_amount":100,"payment_method":"SEPA,Bank transfer","premium":1,"created_at":1627371434},null]}}}"#;
        let message = Message::from_json(sample_message).unwrap();
        assert!(message.verify());
        let message_json = message.as_json().unwrap();
        assert_eq!(message_json, test_message_json);
    }

    #[test]
    fn test_payment_request_payload_message() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(3),
            Action::PayInvoice,
            Some(Payload::PaymentRequest(
                Some(SmallOrder::new(
                    Some(uuid),
                    Some(Kind::Sell),
                    Some(Status::WaitingPayment),
                    100,
                    "eur".to_string(),
                    None,
                    None,
                    100,
                    "Face to face".to_string(),
                    1,
                    None,
                    None,
                    None,
                    Some(1627371434),
                    None,
                )),
                "lnbcrt78510n1pj59wmepp50677g8tffdqa2p8882y0x6newny5vtz0hjuyngdwv226nanv4uzsdqqcqzzsxqyz5vqsp5skn973360gp4yhlpmefwvul5hs58lkkl3u3ujvt57elmp4zugp4q9qyyssqw4nzlr72w28k4waycf27qvgzc9sp79sqlw83j56txltz4va44j7jda23ydcujj9y5k6k0rn5ms84w8wmcmcyk5g3mhpqepf7envhdccp72nz6e".to_string(),
                None,
                None,
            )),
        ));
        let sample_message = r#"{"order":{"version":1,"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","request_id":1,"trade_index":3,"action":"pay-invoice","payload":{"payment_request":[{"id":"308e1272-d5f4-47e6-bd97-3504baea9c23","kind":"sell","status":"waiting-payment","amount":100,"fiat_code":"eur","fiat_amount":100,"payment_method":"Face to face","premium":1,"created_at":1627371434},"lnbcrt78510n1pj59wmepp50677g8tffdqa2p8882y0x6newny5vtz0hjuyngdwv226nanv4uzsdqqcqzzsxqyz5vqsp5skn973360gp4yhlpmefwvul5hs58lkkl3u3ujvt57elmp4zugp4q9qyyssqw4nzlr72w28k4waycf27qvgzc9sp79sqlw83j56txltz4va44j7jda23ydcujj9y5k6k0rn5ms84w8wmcmcyk5g3mhpqepf7envhdccp72nz6e",null,null]}}}"#;
        let message = Message::from_json(sample_message).unwrap();
        assert!(message.verify());
        let message_json = message.as_json().unwrap();
        let test_message_json = test_message.as_json().unwrap();
        assert_eq!(message_json, test_message_json);
    }

    #[test]
    fn test_message_payload_signature() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let peer = Peer::new(
            "npub1testjsf0runcqdht5apkfcalajxkf8txdxqqk5kgm0agc38ke4vsfsgzf8".to_string(),
            None,
        );
        let payload = Payload::Peer(peer);
        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::FiatSentOk,
            Some(payload),
        ));
        assert!(test_message.verify());
        let test_message_json = test_message.as_json().unwrap();
        // Message should be signed with the trade keys
        let trade_keys =
            Keys::parse("110e43647eae221ab1da33ddc17fd6ff423f2b2f49d809b9ffa40794a2ab996c")
                .unwrap();
        let sig = Message::sign(test_message_json.clone(), &trade_keys);

        assert!(Message::verify_signature(
            test_message_json,
            trade_keys.public_key(),
            sig
        ));
    }

    #[test]
    fn test_order_message_with_userinfo() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let payment_methods = "SEPA,Bank transfer".to_string();

        // Create UserInfo for testing
        let user_info = crate::user::UserInfo {
            rating: 4.5,
            reviews: 10,
            operating_days: 30,
        };

        let payload = Payload::Order(
            SmallOrder::new(
                Some(uuid),
                Some(Kind::Sell),
                Some(Status::Pending),
                100,
                "eur".to_string(),
                None,
                None,
                100,
                payment_methods,
                1,
                None,
                None,
                None,
                Some(1627371434),
                None,
            ),
            Some(user_info.clone()),
        );

        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(1),
            Some(2),
            Action::NewOrder,
            Some(payload),
        ));

        // Test serialization and deserialization
        let test_message_json = test_message.as_json().unwrap();
        let deserialized_message = Message::from_json(&test_message_json).unwrap();

        // Verify the message is valid
        assert!(deserialized_message.verify());

        // Verify the UserInfo was preserved
        if let Message::Order(kind) = deserialized_message {
            if let Some(Payload::Order(_, Some(deserialized_user_info))) = kind.payload {
                assert_eq!(deserialized_user_info.rating, user_info.rating);
                assert_eq!(deserialized_user_info.reviews, user_info.reviews);
                assert_eq!(
                    deserialized_user_info.operating_days,
                    user_info.operating_days
                );
            } else {
                panic!("Expected Order payload with UserInfo");
            }
        } else {
            panic!("Expected Order message");
        }
    }

    #[test]
    fn test_order_message_without_userinfo() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let payment_methods = "SEPA,Bank transfer".to_string();

        let payload = Payload::Order(
            SmallOrder::new(
                Some(uuid),
                Some(Kind::Buy),
                Some(Status::Active),
                200,
                "usd".to_string(),
                Some(100),
                Some(500),
                200,
                payment_methods,
                2,
                None,
                None,
                None,
                Some(1627371434),
                Some(1627375034),
            ),
            None, // No UserInfo
        );

        let test_message = Message::Order(MessageKind::new(
            Some(uuid),
            Some(2),
            Some(3),
            Action::NewOrder,
            Some(payload),
        ));

        // Test serialization and deserialization
        let test_message_json = test_message.as_json().unwrap();
        let deserialized_message = Message::from_json(&test_message_json).unwrap();

        // Verify the message is valid
        assert!(deserialized_message.verify());

        // Verify the UserInfo is None
        if let Message::Order(kind) = deserialized_message {
            if let Some(Payload::Order(_, user_info)) = kind.payload {
                assert!(user_info.is_none());
            } else {
                panic!("Expected Order payload");
            }
        } else {
            panic!("Expected Order message");
        }
    }

    #[test]
    fn test_order_message_userinfo_edge_cases() {
        let uuid = uuid!("308e1272-d5f4-47e6-bd97-3504baea9c23");
        let payment_methods = "Cash".to_string();

        // Test with minimum UserInfo values
        let min_user_info = crate::user::UserInfo {
            rating: 0.0,
            reviews: 0,
            operating_days: 0,
        };

        let payload_min = Payload::Order(
            SmallOrder::new(
                Some(uuid),
                Some(Kind::Sell),
                Some(Status::Active),
                50,
                "eur".to_string(),
                None,
                None,
                50,
                payment_methods.clone(),
                0,
                None,
                None,
                None,
                Some(1627371434),
                None,
            ),
            Some(min_user_info.clone()),
        );

        let test_message_min = Message::Order(MessageKind::new(
            Some(uuid),
            Some(3),
            Some(4),
            Action::NewOrder,
            Some(payload_min),
        ));

        // Test serialization and deserialization for minimum values
        let test_message_json = test_message_min.as_json().unwrap();
        let deserialized_message = Message::from_json(&test_message_json).unwrap();
        assert!(deserialized_message.verify());

        // Verify minimum UserInfo values
        if let Message::Order(kind) = deserialized_message {
            if let Some(Payload::Order(_, Some(deserialized_user_info))) = kind.payload {
                assert_eq!(deserialized_user_info.rating, 0.0);
                assert_eq!(deserialized_user_info.reviews, 0);
                assert_eq!(deserialized_user_info.operating_days, 0);
            } else {
                panic!("Expected Order payload with UserInfo");
            }
        } else {
            panic!("Expected Order message");
        }

        // Test with maximum realistic UserInfo values
        let max_user_info = crate::user::UserInfo {
            rating: 5.0,
            reviews: 1000,
            operating_days: 365,
        };

        let payload_max = Payload::Order(
            SmallOrder::new(
                Some(uuid),
                Some(Kind::Buy),
                Some(Status::Active),
                1000,
                "usd".to_string(),
                None,
                None,
                1000,
                payment_methods,
                5,
                None,
                None,
                None,
                Some(1627371434),
                None,
            ),
            Some(max_user_info.clone()),
        );

        let test_message_max = Message::Order(MessageKind::new(
            Some(uuid),
            Some(4),
            Some(5),
            Action::NewOrder,
            Some(payload_max),
        ));

        // Test serialization and deserialization for maximum values
        let test_message_json_max = test_message_max.as_json().unwrap();
        let deserialized_message_max = Message::from_json(&test_message_json_max).unwrap();
        assert!(deserialized_message_max.verify());

        // Verify maximum UserInfo values
        if let Message::Order(kind) = deserialized_message_max {
            if let Some(Payload::Order(_, Some(deserialized_user_info))) = kind.payload {
                assert_eq!(deserialized_user_info.rating, 5.0);
                assert_eq!(deserialized_user_info.reviews, 1000);
                assert_eq!(deserialized_user_info.operating_days, 365);
            } else {
                panic!("Expected Order payload with UserInfo");
            }
        } else {
            panic!("Expected Order message");
        }
    }

    #[test]
    fn test_cant_do_message_serialization() {
        // Test all CantDoReason variants
        let reasons = vec![
            CantDoReason::InvalidSignature,
            CantDoReason::InvalidTradeIndex,
            CantDoReason::InvalidAmount,
            CantDoReason::InvalidInvoice,
            CantDoReason::InvalidPaymentRequest,
            CantDoReason::InvalidPeer,
            CantDoReason::InvalidRating,
            CantDoReason::InvalidTextMessage,
            CantDoReason::InvalidOrderStatus,
            CantDoReason::InvalidPubkey,
            CantDoReason::InvalidParameters,
            CantDoReason::OrderAlreadyCanceled,
            CantDoReason::CantCreateUser,
            CantDoReason::IsNotYourOrder,
            CantDoReason::NotAllowedByStatus,
            CantDoReason::OutOfRangeFiatAmount,
            CantDoReason::OutOfRangeSatsAmount,
            CantDoReason::IsNotYourDispute,
            CantDoReason::NotFound,
            CantDoReason::InvalidFiatCurrency,
            CantDoReason::TooManyRequests,
        ];

        for reason in reasons {
            let cant_do = Message::CantDo(MessageKind::new(
                None,
                None,
                None,
                Action::CantDo,
                Some(Payload::CantDo(Some(reason.clone()))),
            ));
            let message = Message::from_json(&cant_do.as_json().unwrap()).unwrap();
            assert!(message.verify());
            assert_eq!(message.as_json().unwrap(), cant_do.as_json().unwrap());
        }

        // Test None case
        let cant_do = Message::CantDo(MessageKind::new(
            None,
            None,
            None,
            Action::CantDo,
            Some(Payload::CantDo(None)),
        ));
        let message = Message::from_json(&cant_do.as_json().unwrap()).unwrap();
        assert!(message.verify());
        assert_eq!(message.as_json().unwrap(), cant_do.as_json().unwrap());
    }
}
