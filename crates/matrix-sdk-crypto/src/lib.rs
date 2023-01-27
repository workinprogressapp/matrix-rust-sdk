// Copyright 2020 The Matrix.org Foundation C.I.C.
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
/// A step by step guide that explains how to include end-to-end-encryption
/// support in a client library.
///
/// # Table of contents
/// 1. [Introduction](#introduction)
/// 2. [Initialization and initial setup](#initializing-the-state-machine)
/// 3. [Decrypting room events](decryption)
/// 4. [Encrypting room events](encryption)
/// 5. [Interactively verifying devices and user identities](verification)
///
/// # Introduction
///
/// TODO
///
/// # Initializing the state machine
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
/// This will create a `OlmMachine` that does not persist any data TODO
///
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
/// 1. Upload your devices identity keys and a set of one-time keys.
/// 2. Receive room keys that were encrypted for your specific device and
///    decrypt them.
/// 3. Decrypt room events.
///
/// 1. Send outgoing requests out, this uploads your devices identity keys and
/// one-time keys.
///
/// 2. Receive sync changes, this pushes room keys into the state
/// machine
///
/// 3. Decrypt room events.
///
///
/// The simplified flowchart
///
/// ```mermaid
/// graph TD;
///     sync[Sync with the homeserver]
///     receive_changes[Push E2EE related changes into the state machine]
///     send_outgoing_requests[Send all outgoing requests to the homeserver]
///     decrypt[Process the rest of the sync]
///
///     click receive_changes callback "OlmMachine::receive_sync_changes()"
///
///     sync --> receive_changes;
///     receive_changes --> send_outgoing_requests;
///     send_outgoing_requests --> decrypt;
///     decrypt -- repeat --> sync;
/// ```
///
/// ## Uploading identity and one-time keys.
///
/// ## Receiving room keys and related changes
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
/// # Encryption
///
/// TODO
///
///
/// # Verification
///
/// TODO
pub mod tutorial {}
