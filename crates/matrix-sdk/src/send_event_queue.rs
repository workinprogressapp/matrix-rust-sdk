use std::collections::VecDeque;

use ruma::api::client::{message::send_message_event, state::send_state_event};
use tokio::sync::oneshot;

use crate::Result;

pub type SendEventQueue = VecDeque<SendEventRequest>;

pub enum SendEventRequest {
    MessageLike(send_message_event::v3::Request),
    State(send_state_event::v3::Request),
}

#[derive(Debug)]
pub struct SendMessageLikeEventHandle {
    recv: oneshot::Receiver<Result<send_message_event::v3::Response>>,
}

#[derive(Debug)]
pub struct SendStateEventHandle {
    recv: oneshot::Receiver<Result<send_state_event::v3::Response>>,
}

fn foo() {}
