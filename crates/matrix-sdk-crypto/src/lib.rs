// Copyright 2020 The Matrix.org Foundation C.I.C.
// Copyright 2023 Damir Jelić
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, missing_debug_implementations)]

#[cfg(feature = "backups_v1")]
pub mod backups;
mod error;
mod file_encryption;
mod gossiping;
mod identities;
mod machine;
pub mod olm;
pub mod requests;
mod session_manager;
pub mod store;
pub mod types;
mod utilities;
mod verification;

#[cfg(feature = "testing")]
/// Testing facilities and helpers for crypto tests
pub mod testing {
    pub use crate::identities::{
        device::testing::get_device,
        user::testing::{get_other_identity, get_own_identity},
    };
}

use std::collections::{BTreeMap, BTreeSet};

use ruma::OwnedRoomId;

/// Return type for the room key importing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomKeyImportResult {
    /// The number of room keys that were imported.
    pub imported_count: usize,
    /// The total number of room keys that were found in the export.
    pub total_count: usize,
    /// The map of keys that were imported.
    ///
    /// It's a map from room id to a map of the sender key to a set of session
    /// ids.
    pub keys: BTreeMap<OwnedRoomId, BTreeMap<String, BTreeSet<String>>>,
}

impl RoomKeyImportResult {
    pub(crate) fn new(
        imported_count: usize,
        total_count: usize,
        keys: BTreeMap<OwnedRoomId, BTreeMap<String, BTreeSet<String>>>,
    ) -> Self {
        Self { imported_count, total_count, keys }
    }
}

pub use error::{EventError, MegolmError, OlmError, SessionCreationError, SignatureError};
pub use file_encryption::{
    decrypt_room_key_export, encrypt_room_key_export, AttachmentDecryptor, AttachmentEncryptor,
    DecryptorError, KeyExportError, MediaEncryptionInfo,
};
pub use gossiping::GossipRequest;
pub use identities::{
    Device, LocalTrust, MasterPubkey, OwnUserIdentity, ReadOnlyDevice, ReadOnlyOwnUserIdentity,
    ReadOnlyUserIdentities, ReadOnlyUserIdentity, UserDevices, UserIdentities, UserIdentity,
};
pub use machine::OlmMachine;
#[cfg(feature = "qrcode")]
pub use matrix_sdk_qrcode;
pub use olm::{CrossSigningStatus, EncryptionSettings, ReadOnlyAccount};
pub use requests::{
    IncomingResponse, KeysBackupRequest, KeysQueryRequest, OutgoingRequest, OutgoingRequests,
    OutgoingVerificationRequest, RoomMessageRequest, ToDeviceRequest, UploadSigningKeysRequest,
};
pub use store::{
    CrossSigningKeyExport, CryptoStoreError, SecretImportError, SecretInfo, TrackedUser,
};
pub use verification::{
    format_emojis, AcceptSettings, AcceptedProtocols, CancelInfo, Emoji, EmojiShortAuthString, Sas,
    SasState, Verification, VerificationRequest, VerificationRequestState,
};
#[cfg(feature = "qrcode")]
pub use verification::{QrVerification, QrVerificationState, ScanError};

/// Re-exported Error types from the [vodozemac](https://crates.io/crates/vodozemac) crate.
pub mod vodozemac {
    pub use vodozemac::{
        megolm::{DecryptionError as MegolmDecryptionError, SessionKeyDecodeError},
        olm::{
            DecryptionError as OlmDecryptionError, SessionCreationError as OlmSessionCreationError,
        },
        DecodeError, KeyError, PickleError, SignatureError,
    };
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// A step by step guide that explains how to include [end-to-end-encryption]
/// support in a [Matrix] client library.
///
/// This crate implements a [sans-network-io](https://sans-io.readthedocs.io/)
/// state machine that allows you to add [end-to-end-encryption] support to a
/// [Matrix] client library.
///
/// This guide aims to provide a comprehensive understanding of end-to-end
/// encryption in Matrix without any prior knowledge requirements. However, it
/// is recommended that the reader has a basic understanding of Matrix and its
/// [client-server specification] for a more informed and efficient learning
/// experience.
///
/// The [introductory](#introduction) section provides a simplified explanation
/// of end-to-end encryption and its implementation in Matrix for those who may
/// not have prior knowledge. If you already have a solid understanding of
/// end-to-end encryption, including the [Olm] and [Megolm] protocols, you may
/// choose to skip directly to the [Getting Started](#getting-started) section.
///
/// # Table of contents
/// 1. [Introduction](#introduction)
/// 2. [Getting started](#getting-started)
/// 3. [Decrypting room events](decryption)
/// 4. [Encrypting room events](encryption)
/// 5. [Interactively verifying devices and user identities](verification)
///
/// # Introduction
///
/// Welcome to the first part of this guide, where we will introduce the
/// fundamental concepts of end-to-end encryption and its implementation in
/// Matrix.
///
/// This section will provide a clear and concise overview of what
/// end-to-end encryption is and why it is important for secure communication.
/// You will also learn about how Matrix uses end-to-end encryption to protect
/// the privacy and security of its users' communications. Whether you are new
/// to the topic or simply want to improve your understanding, this section will
/// serve as a solid foundation for the rest of the guide.
///
/// Let's dive in!
///
/// ## Notation
///
/// ## End-to-end-encryption
///
/// End-to-end encryption (E2EE) is a method of secure communication where only
/// the communicating devices, also known as "the ends," can read the data being
/// transmitted. This means that the data is encrypted on one device, and can
/// only be decrypted on the other device. The server is used only as a
/// transport mechanism to deliver messages between devices.
///
/// The following chart displays how communication between two clients using a
/// server in the middle usually works.
///
/// ```mermaid
/// flowchart LR
///     alice[Alice]
///     bob[Bob]
///     subgraph Homeserver
///         direction LR
///         outbox[Alice outbox]
///         inbox[Bob inbox]
///         outbox -. unencrypted .-> inbox
///     end
///
///     alice -- encrypted --> outbox
///     inbox -- encrypted --> bob
/// ```
///
/// The next chart, instead, displays how the same flow is happening in a
/// end-to-end-encrypted world.
///
/// ```mermaid
/// flowchart LR
///     alice[Alice]
///     bob[Bob]
///     subgraph Homeserver
///         direction LR
///         outbox[Alice outbox]
///         inbox[Bob inbox]
///         outbox == encrypted ==> inbox
///     end
///
///     alice == encrypted ==> outbox
///     inbox == encrypted ==> bob
/// ```
///
/// Note that the path from the outbox to the inbox is now encrypted as well.
///
/// Alice and Bob have created a secure communication channel
/// through which they can exchange messages confidentially, without the risk of
/// the server accessing the contents of their messages.
///
/// ## Publishing cryptographic identities of devices
///
/// If Alice and Bob want to establish a secure channel over which they can
/// exchange messages, they first need learn about each others cryptographic
/// identities. This is achieved by using the homeserver as a public key
/// directory.
///
/// A public key directory is used to store and distribute public keys of users
/// in an end-to-end encrypted system. The basic idea behind a public key
/// directory is that it allows users to easily discover and download the public
/// keys of other users with whom they wish to establish an end-to-end encrypted
/// communication.
///
/// Each user generates a pair of public and private keys. The user then uploads
/// their public key to the public key directory. Other users can then search
/// the directory to find the public key of the user they wish to communicate
/// with, and download it to their own device.
///
/// ```mermaid
/// flowchart LR
///     alice[Alice]
///     subgraph homeserver[Homeserver]
///         direction LR
///         directory[(Public key directory)]
///     end
///     bob[Bob]
///
///     alice -- upload keys --> directory
///     directory -- download keys --> bob
/// ```
///
/// Once a user has the other user's public key, they can use it to establish an
/// end-to-end encrypted channel using a [key-agreement] protocol.
///
/// ## Using the Triple Diffie-Hellman key-agreement protocol
///
/// In X3DH, each user generates a long-term identity key pair and a set of
/// one-time prekeys. When two users want to establish a shared secret key, they
/// exchange their public identity keys and one of their prekeys. These public
/// keys are then used in a [Diffie-Hellman] key exchange to compute a shared
/// secret key.
///
/// The use of one-time prekeys ensures that the shared secret key is different
/// for each session, even if the same identity keys are used.
///
/// ```mermaid
/// flowchart LR
/// subgraph alice_keys[Alice Keys]
///     direction TB
///     alice_key[Alice's identity key]
///     alice_base_key[Alice's one-time key]
/// end
///
/// subgraph bob_keys[Bob Keys]
///     direction TB
///     bob_key[Bob's identity key]
///     bob_one_time[Bob's one-time key]
/// end
///
/// alice_key <--> bob_one_time
/// alice_base_key <--> bob_one_time
/// alice_base_key <--> bob_key
/// ```
///
/// Similar to [X3DH] (Extended Triple Diffie-Hellman) key agreement protocol
///
/// ## Speeding up encryption for large groups
///
/// TODO Explain how megolm fits into this
///
/// # Getting started
///
/// In the [Matrix] world the server is called a [homeserver]
///
/// ## Push/pull mechanism
///
/// ```mermaid
/// flowchart LR
///     homeserver[Homeserver]
///     client[OlmMachine]
///
///     homeserver -- pull --> client
///     client -- push --> homeserver
/// ```
///
/// ## Initializing the state machine
///
/// ```
/// use anyhow::Result;
/// use matrix_sdk_crypto::OlmMachine;
/// use ruma::user_id;
///
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// let user_id = user_id!("@alice:localhost");
/// let device_id = "DEVICEID".into();
///
/// let machine = OlmMachine::new(user_id, device_id).await;
/// # Ok(())
/// # }
/// ```
///
/// This will create a [`OlmMachine`] that does not persist any data TODO
/// ```ignore
/// use anyhow::Result;
/// use matrix_sdk_crypto::OlmMachine;
/// use matrix_sdk_sled::SledCryptoStore;
/// use ruma::user_id;
///
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// let user_id = user_id!("@alice:localhost");
/// let device_id = "DEVICEID".into();
///
/// let store = SledCryptoStore::open("/home/example/matrix-client/").await?;
///
/// let machine = OlmMachine::with_store(user_id, device_id, store).await;
/// # Ok(())
/// # }
/// ```
///
/// # Decryption
///
/// In the world of encrypted communication, it is common to start with the
/// encryption step when implementing a protocol. However, in the case of adding
/// end-to-end encryption support to a Matrix client library, a simpler approach
/// is to first focus on the decryption process. This is because there are
/// already Matrix clients in existence that support encryption, which means
/// that our client library can simply receive encrypted messages and then
/// decrypt them.
///
/// In this section, we will guide you through the minimal steps
/// necessary to get the decryption process up and running using the
/// matrix-sdk-crypto Rust crate. By the end of this section you should have a
/// Matrix client that is able to decrypt room events that other clients have
/// sent.
///
/// To enable decryption the following three steps are needed:
///
/// 1. [The cryptographic identity of your device needs to be published to the
/// homeserver](#uploading-identity-and-one-time-keys).
/// 2. [Decryption keys coming in from other devices need to be processed and
/// stored](#receiving-room-keys-and-related-changes).
/// 3. [Individual messages need to be decrypted](#decrypting-room-events).
///
/// The simplified flowchart
/// ```mermaid
/// graph TD
///     sync[Sync with the homeserver]
///     receive_changes[Push E2EE related changes into the state machine]
///     send_outgoing_requests[Send all outgoing requests to the homeserver]
///     decrypt[Process the rest of the sync]
///
///     sync --> receive_changes;
///     receive_changes --> send_outgoing_requests;
///     send_outgoing_requests --> decrypt;
///     decrypt -- repeat --> sync;
/// ```
///
/// ## Uploading identity and one-time keys.
///
/// The first step is to announce the support for it to other users in the
/// Matrix network. This involves publishing your long-term device keys and a
/// set of one-time prekeys to the homeserver. This information is used by other
/// devices to encrypt messages specifically for your device.
///
/// To achieve this, you will need to extract any requests that need to be sent
/// to the homeserver from the [`OlmMachine`] and send them to the homeserver.
/// The following snipped showcases how to achieve this using the
/// [`OlmMachine::outgoing_requests()`] method:
///
/// ```no_run
/// # use std::collections::BTreeMap;
/// # use ruma::api::client::keys::upload_keys::v3::Response;
/// # use anyhow::Result;
/// # use matrix_sdk_crypto::{OlmMachine, OutgoingRequest};
/// # async fn send_request(request: OutgoingRequest) -> Result<Response> {
/// #     let response = unimplemented!();
/// #     Ok(response)
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let machine: OlmMachine = unimplemented!();
/// // Get all the outgoing requests.
/// let outgoing_requests = machine.outgoing_requests().await?;
///
/// // Send each request to the server and push the response into the state machine.
/// for request in outgoing_requests {
///     // You can safely send out these requests out in parallel.
///     let request_id = request.request_id();
///     let response = send_request(request).await?;
///     machine.mark_request_as_sent(&request_id, &response).await?;
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Receiving room keys and related changes
///
/// ```no_run
/// # use std::collections::BTreeMap;
/// # use anyhow::Result;
/// # use matrix_sdk_crypto::OlmMachine;
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let to_device_events = Vec::new();
/// # let changed_devices = Default::default();
/// # let one_time_key_counts = BTreeMap::default();
/// # let unused_fallback_keys = Some(Vec::new());
/// # let machine: OlmMachine = unimplemented!();
/// // Push changes that the server sent to us in a sync response.
/// let decrypted_to_device = machine
///     .receive_sync_changes(
///         to_device_events,
///         &changed_devices,
///         &one_time_key_counts,
///         unused_fallback_keys.as_deref(),
///     )
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Decrypting room events
///
/// The final step in the decryption process is to decrypt the room events that
/// are received from the server. To do this, the encrypted events must be
/// passed to the [`OlmMachine`], which will use the keys that were previously
/// exchanged between devices to decrypt the events. The decrypted events can
/// then be processed and displayed to the user in the Matrix client.
///
/// Room events can be decrypted using the [`OlmMachine::decrypt_room_event()`]
/// method.
///
/// ```no_run
/// # use std::collections::BTreeMap;
/// # use anyhow::Result;
/// # use matrix_sdk_crypto::OlmMachine;
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let encrypted = unimplemented!();
/// # let room_id = unimplemented!();
/// # let machine: OlmMachine = unimplemented!();
/// // Decrypt your room events now.
/// let decrypted = machine.decrypt_room_event(encrypted, room_id).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Encryption
///
/// TODO
///
/// ```mermaid
/// sequenceDiagram
/// actor Alice
/// participant Homeserver
/// actor Bob
///
/// Alice->>Homeserver: Download Bob's one-time
/// Homeserver->>Alice: Bob's one-time keys
/// Alice->>Alice: Encrypt the room key
/// Alice->>Homeserver: Send the room key to each of Bob's devices
/// Homeserver->>Bob: Deliver the room key
/// Alice->>Alice: Encrypt the message
/// Alice->>Homeserver: Send the encrypted message
/// Homeserver->>Bob: Deliver the encrypted message
/// ```
///
/// TODO
///
/// ## Tracking users
///
/// ```no_run
/// # use std::collections::{BTreeMap, HashSet};
/// # use anyhow::Result;
/// # use ruma::UserId;
/// # use matrix_sdk_crypto::OlmMachine;
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let users: HashSet<&UserId> = HashSet::new();
/// # let machine: OlmMachine = unimplemented!();
/// // Mark all the users that are part of an encrypted room as tracked
/// machine.update_tracked_users(users).await?;
/// # Ok(())
/// # }
/// ```
///
/// TODO
///
/// ## Establishing end-to-end encrypted channels
///
/// TODO
///
/// ```no_run
/// # use std::collections::{BTreeMap, HashSet};
/// # use std::ops::Deref;
/// # use anyhow::Result;
/// # use ruma::UserId;
/// # use ruma::api::client::keys::claim_keys::v3::{Response, Request};
/// # use matrix_sdk_crypto::OlmMachine;
/// # async fn send_request(request: &Request) -> Result<Response> {
/// #     let response = unimplemented!();
/// #     Ok(response)
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let users: HashSet<&UserId> = HashSet::new();
/// # let machine: OlmMachine = unimplemented!();
/// // Mark all the users that are part of an encrypted room as tracked
/// if let Some((request_id, request)) =
///     machine.get_missing_sessions(users.iter().map(Deref::deref)).await?
/// {
///     let response = send_request(&request).await?;
///     machine.mark_request_as_sent(&request_id, &response).await?;
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Exchanging room keys
///
/// TODO
///
/// ```no_run
/// # use std::collections::{BTreeMap, HashSet};
/// # use std::ops::Deref;
/// # use anyhow::Result;
/// # use ruma::UserId;
/// # use ruma::api::client::keys::claim_keys::v3::{Response, Request};
/// # use matrix_sdk_crypto::{OlmMachine, requests::ToDeviceRequest, EncryptionSettings};
/// # async fn send_request(request: &ToDeviceRequest) -> Result<Response> {
/// #     let response = unimplemented!();
/// #     Ok(response)
/// # }
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let users: HashSet<&UserId> = HashSet::new();
/// # let room_id = unimplemented!();
/// # let settings = EncryptionSettings::default();
/// # let machine: OlmMachine = unimplemented!();
/// // Mark all the users that are part of an encrypted room as tracked
/// let requests = machine.share_room_key(
///     room_id,
///     users.iter().map(Deref::deref),
///     settings
/// ).await?;
///
/// for request in requests {
///     let request_id = &request.txn_id;
///     let response = send_request(&request).await?;
///     machine.mark_request_as_sent(&request_id, &response).await?;
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Encrypting room events
///
/// ```no_run
/// # use anyhow::Result;
/// # use matrix_sdk_crypto::OlmMachine;
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
/// # let room_id = unimplemented!();
/// # let event = unimplemented!();
/// # let machine: OlmMachine = unimplemented!();
/// // Decrypt each room event you'd like to display to the user using this method.
/// let decrypted = machine.decrypt_room_event(event, room_id)?;
/// # Ok(())
/// # }
/// ```

///
/// TODO
///
///
/// # Verification
///
/// TODO
///
/// [Matrix]: https://matrix.org/
/// [Olm]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md
/// [Diffie-Hellman]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
/// [Megolm]: https://gitlab.matrix.org/matrix-org/olm/blob/master/docs/megolm.md
/// [end-to-end-encryption]: https://en.wikipedia.org/wiki/End-to-end_encryption
/// [homeserver]: https://spec.matrix.org/unstable/#architecture
/// [key-agreement]: https://en.wikipedia.org/wiki/Key-agreement_protocol
/// [client-server specification]: https://matrix.org/docs/spec/client_server/
/// [forward secrecy]: https://en.wikipedia.org/wiki/Forward_secrecy
/// [replay attacks]: https://en.wikipedia.org/wiki/Replay_attack
///
/// [X3DH]: https://signal.org/docs/specifications/x3dh/
pub mod tutorial {}
