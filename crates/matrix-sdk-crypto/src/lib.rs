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
/// If you're not familiar with Matrix or how clients communicate with a Matrix
/// homeserver it's advised to get yourself familiar with the [client-server spec](https://matrix.org/docs/spec/client_server/)
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
/// This crate implements a [sans-network-io](https://sans-io.readthedocs.io/) state machine that
/// allows you to add [end-to-end-encryption] support to a [Matrix] client
/// library.
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
///     subgraph Server
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
///     subgraph Server
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
/// Once a user has the other user's public key, they can use it to establish an
/// end-to-end encrypted channel using a [key-agreement] protocol.
///
/// ```mermaid
/// flowchart LR
///     alice[Alice]
///     subgraph server[Server]
///         direction LR
///         directory[(Public key directory)]
///     end
///     bob[Bob]
///
///     alice -- upload keys --> directory
///     directory -- download keys --> bob
/// ```
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
/// To enable decryption the following three steps are needed:
///
/// 1. [The cryptographic identity of your device needs to be published to the
/// homeserver](#uploading-identity-and-one-time-key)
/// 2. [Decryption keys coming in from other devices need to be processed and
/// stored](#receiving-room-keys-and-related-changes)
/// 3. [Messages need to be decrypted](#decrypting-room-events)
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
/// TODO
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
/// TODO
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
/// TODO
///
///
/// # Verification
///
/// TODO
///
/// [Matrix]: https://matrix.org/
/// [end-to-end-encryption]: https://en.wikipedia.org/wiki/End-to-end_encryption
/// [homeserver]: https://spec.matrix.org/unstable/#architecture
/// [key-agreement]: https://en.wikipedia.org/wiki/Key-agreement_protocol
///
/// [X3DH]: https://signal.org/docs/specifications/x3dh/
/// [diffie-hellman]: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
pub mod tutorial {}
