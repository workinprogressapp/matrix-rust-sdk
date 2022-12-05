#![allow(dead_code, unused, clippy::todo)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    path::Path,
    sync::Arc,
};

use async_trait::async_trait;
use matrix_sdk_common::locks::Mutex;
use matrix_sdk_crypto::{
    olm::{
        InboundGroupSession, OlmMessageHash, OutboundGroupSession, PrivateCrossSigningIdentity,
        Session,
    },
    store::{BackupKeys, Changes, CryptoStore, Result, RoomKeyCounts},
    CryptoStoreError, GossipRequest, ReadOnlyAccount, ReadOnlyDevice, ReadOnlyUserIdentities,
    SecretInfo,
};
use matrix_sdk_store_encryption::StoreCipher;
use ruma::{DeviceId, OwnedDeviceId, OwnedUserId, RoomId, TransactionId, UserId};
use sanakirja::{
    btree::{self, create_db_, UDb},
    Commit as _, Env, MutTxn, RootDb as _, Slice, Txn,
};
use serde::{de::DeserializeOwned, Serialize};

pub struct SanakirjaCryptoStore {
    env: Env,
    store_cipher: Option<Arc<StoreCipher>>,
}

impl fmt::Debug for SanakirjaCryptoStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { env: _, store_cipher: _ } = self;
        f.debug_struct("SanakirjaCryptoStore").finish_non_exhaustive()
    }
}

const INITIAL_NUM_PAGES: u64 = 256;
const INITIAL_DB_SIZE: u64 = INITIAL_NUM_PAGES * 4096;

mod db {
    pub const DB_VERSION: usize = 0;
    pub const DB_METADATA: usize = 1;
    pub const OWN_USER: usize = 2;
    pub const OLM_HASHES: usize = 3;
    pub const SESSIONS: usize = 4;
    pub const INBOUND_GROUP_SESSIONS: usize = 5;
    pub const OUTBOUND_GROUP_SESSIONS: usize = 6;
    pub const OUTGOING_SECRET_REQUESTS: usize = 7;
    pub const SECRET_REQUESTS_BY_INFO: usize = 8;
    pub const DEVICES: usize = 9;
    pub const IDENTITIES: usize = 10;
    pub const TRACKED_USERS: usize = 11;
    pub const NUM_DBS: usize = 12;
}

mod error {
    use thiserror::Error;

    /// A DB version is set, but other database parts that should be there on
    /// that version are missing.
    #[derive(Debug, Error)]
    #[error("Database is corrupted (partially initialized)")]
    pub(super) struct PartiallyInitialized;

    /// This database is not passphrase-protected, yet a passphrase was given.
    #[derive(Debug, Error)]
    #[error("Passed a passphrase for a DB that isn't passphrase-protected")]
    pub(super) struct DbHasNoPassphrase;

    /// This database is passphrase-protected, but none was given.
    #[derive(Debug, Error)]
    #[error("Omitted the passphrase for a DB that is passphrase-protected")]
    pub(super) struct MissingPassphrase;
}

// Allow one old version of the DB to continue existing while a writer has
// exclusive ownership of the other one.
const N_ROOTS: usize = 2;

impl SanakirjaCryptoStore {
    const CURRENT_DB_VERSION: u64 = 1;

    pub fn open(/* path: impl AsRef<Path>, */ passphrase: Option<&str>) -> Result<Self> {
        //std::fs::create_dir_all(&path)?;
        //let path = path.as_ref().join("matrix-sdk-crypto");
        let env = Env::new_anon(INITIAL_DB_SIZE, N_ROOTS).map_err(CryptoStoreError::backend)?;

        // Start off with a readonly transaction so we skip unnecessary
        // locking in the common case of the DB already being initialized.
        let txn = Env::txn_begin(&env).map_err(CryptoStoreError::backend)?;

        // Ranges are overlapping, but there is no nicer way to write this
        // without inline const blocks
        #[allow(overlapping_range_endpoints)]
        let store_cipher = match txn.root(db::DB_VERSION) {
            // DB isn't initialized yet
            0 => {
                // Make sure the readonly transaction is dropped before
                // attempting to begin a read-write transaction.
                drop(txn);

                // FIXME: On MSRV >= 1.66, use map + transpose + unzip
                let (cipher, cipher_export) = match passphrase {
                    Some(p) => {
                        let (cipher, cipher_export) =
                            create_store_cipher(p).map_err(CryptoStoreError::backend)?;
                        (Some(cipher), Some(cipher_export))
                    }
                    None => (None, None),
                };

                create_db(&env, cipher_export.as_deref()).map_err(CryptoStoreError::backend)?;

                cipher
            }
            // DB is at the current version
            Self::CURRENT_DB_VERSION => {
                let cipher = get_store_cipher(&txn, passphrase)?;

                // txn has lexical lifetime because it has a custom `Drop` impl,
                // so it has to be dropped manually before `env` can be moved
                // (as part of the return value)
                drop(txn);

                cipher
            }
            // DB is at a lower version - currently unreachable
            /* v @ 1..=Self::CURRENT_DB_VERSION => todo!(), */
            // DB is at a higher version
            v @ Self::CURRENT_DB_VERSION.. => {
                return Err(CryptoStoreError::UnsupportedDatabaseVersion(
                    v as _,
                    Self::CURRENT_DB_VERSION as _,
                ));
            }
        };

        Ok(Self { env, store_cipher })
    }

    fn begin_txn(&self) -> Result<Txn<&Env>> {
        Env::txn_begin(&self.env).map_err(CryptoStoreError::backend)
    }

    fn begin_mut_txn(&self) -> Result<MutTxn<&Env, ()>> {
        Env::mut_txn_begin(&self.env).map_err(CryptoStoreError::backend)
    }

    fn serialize_value(&self, event: &impl Serialize) -> Result<Vec<u8>> {
        match &self.store_cipher {
            Some(cipher) => cipher.encrypt_value(event).map_err(CryptoStoreError::backend),
            _ => Ok(serde_json::to_vec(event)?),
        }
    }

    fn deserialize_value<T: DeserializeOwned>(&self, value: &[u8]) -> Result<T> {
        match &self.store_cipher {
            Some(cipher) => cipher.decrypt_value(value).map_err(CryptoStoreError::backend),
            None => Ok(serde_json::from_slice(value)?),
        }
    }
}

fn create_db(env: &Env, store_cipher: Option<&[u8]>) -> Result<(), sanakirja::Error> {
    let mut txn_ = Env::mut_txn_begin(env)?;
    let txn = &mut txn_;

    let mut db_metadata: UDb<Slice<'_>, Slice<'_>> = create_db_(txn)?;
    if let Some(cipher) = store_cipher {
        btree::put(txn, &mut db_metadata, &b"store_cipher".as_slice().into(), &cipher.into())?;
    }
    txn.set_root(db::DB_METADATA, db_metadata.db);

    let account_db: UDb<Slice<'_>, Slice<'_>> = create_db_(txn)?;
    txn.set_root(db::OWN_USER, account_db.db);

    txn_.commit()?;

    Ok(())
}

fn create_store_cipher(
    passphrase: &str,
) -> Result<(Arc<StoreCipher>, Vec<u8>), matrix_sdk_store_encryption::Error> {
    let cipher = Arc::new(StoreCipher::new()?);
    #[cfg(not(test))]
    let cipher_export = cipher.export(passphrase)?;
    #[cfg(test)]
    let cipher_export = cipher._insecure_export_fast_for_testing(passphrase)?;

    Ok((cipher, cipher_export))
}

fn get_store_cipher(
    txn: &Txn<&Env>,
    passphrase: Option<&str>,
) -> Result<Option<Arc<StoreCipher>>, CryptoStoreError> {
    let db_metadata: UDb<Slice<'_>, Slice<'_>> = txn
        .root_db(db::DB_METADATA)
        .ok_or_else(|| CryptoStoreError::backend(error::PartiallyInitialized))?;
    let store_cipher_export =
        btree::get(txn, &db_metadata, &b"store_cipher".as_slice().into(), None)
            .map_err(CryptoStoreError::backend)?;

    match (passphrase, store_cipher_export) {
        (Some(_), None) => Err(CryptoStoreError::backend(error::DbHasNoPassphrase)),
        (None, Some(_)) => Err(CryptoStoreError::backend(error::MissingPassphrase)),
        (Some(p), Some((_, encrypted))) => {
            let bytes = &encrypted.as_bytes(txn).map_err(CryptoStoreError::backend)?;
            Ok(Some(Arc::new(StoreCipher::import(p, bytes).map_err(CryptoStoreError::backend)?)))
        }
        (None, None) => Ok(None),
    }
}

#[async_trait]
impl CryptoStore for SanakirjaCryptoStore {
    async fn load_account(&self) -> Result<Option<ReadOnlyAccount>> {
        let txn = self.begin_txn()?;
        let own_user: UDb<Slice<'_>, Slice<'_>> = txn
            .root_db(db::OWN_USER)
            .ok_or_else(|| CryptoStoreError::backend(error::PartiallyInitialized))?;

        if let Some((_, value)) = btree::get(&txn, &own_user, &b"account".as_slice().into(), None)
            .map_err(CryptoStoreError::backend)?
        {
            let bytes = value.as_bytes(&txn).map_err(CryptoStoreError::backend)?;
            let pickled_account = self.deserialize_value(bytes)?;
            let account = ReadOnlyAccount::from_pickle(pickled_account)?;
            /* let account_info = AccountInfo {
                user_id: account.user_id.clone(),
                device_id: account.device_id.clone(),
                identity_keys: account.identity_keys.lcone(),
            }; */

            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    async fn save_account(&self, account: ReadOnlyAccount) -> Result<()> {
        let pickled_account = account.pickle().await;
        let mut txn = self.begin_mut_txn()?;
        let mut own_user: UDb<Slice<'_>, Slice<'_>> = txn
            .root_db(db::OWN_USER)
            .ok_or_else(|| CryptoStoreError::backend(error::PartiallyInitialized))?;
        btree::put(
            &mut txn,
            &mut own_user,
            &b"account".as_slice().into(),
            &self.serialize_value(&pickled_account)?.as_slice().into(),
        )
        .map_err(CryptoStoreError::backend)?;
        txn.commit().map_err(CryptoStoreError::backend)?;

        Ok(())
    }

    async fn load_identity(&self) -> Result<Option<PrivateCrossSigningIdentity>> {
        todo!()
    }

    async fn save_changes(&self, changes: Changes) -> Result<()> {
        todo!()
    }

    async fn get_sessions(&self, sender_key: &str) -> Result<Option<Arc<Mutex<Vec<Session>>>>> {
        todo!()
    }

    async fn get_inbound_group_session(
        &self,
        room_id: &RoomId,
        session_id: &str,
    ) -> Result<Option<InboundGroupSession>> {
        todo!()
    }

    async fn get_inbound_group_sessions(&self) -> Result<Vec<InboundGroupSession>> {
        todo!()
    }

    async fn inbound_group_session_counts(&self) -> Result<RoomKeyCounts> {
        todo!()
    }

    async fn inbound_group_sessions_for_backup(
        &self,
        limit: usize,
    ) -> Result<Vec<InboundGroupSession>> {
        todo!()
    }

    async fn reset_backup_state(&self) -> Result<()> {
        // TODO
        Ok(())
    }

    async fn load_backup_keys(&self) -> Result<BackupKeys> {
        // TODO
        Ok(Default::default())
    }

    async fn get_outbound_group_sessions(
        &self,
        room_id: &RoomId,
    ) -> Result<Option<OutboundGroupSession>> {
        todo!()
    }

    fn is_user_tracked(&self, user_id: &UserId) -> bool {
        todo!()
    }

    fn has_users_for_key_query(&self) -> bool {
        todo!()
    }

    fn users_for_key_query(&self) -> HashSet<OwnedUserId> {
        todo!()
    }

    fn tracked_users(&self) -> HashSet<OwnedUserId> {
        todo!()
    }

    async fn update_tracked_user(&self, user: &UserId, dirty: bool) -> Result<bool> {
        todo!()
    }

    async fn get_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<Option<ReadOnlyDevice>> {
        todo!()
    }

    async fn get_user_devices(
        &self,
        user_id: &UserId,
    ) -> Result<HashMap<OwnedDeviceId, ReadOnlyDevice>> {
        todo!()
    }

    async fn get_user_identity(&self, user_id: &UserId) -> Result<Option<ReadOnlyUserIdentities>> {
        todo!()
    }

    async fn is_message_known(&self, message_hash: &OlmMessageHash) -> Result<bool> {
        todo!()
    }

    async fn get_outgoing_secret_requests(
        &self,
        _request_id: &TransactionId,
    ) -> Result<Option<GossipRequest>> {
        // TODO
        Ok(None)
    }

    async fn get_secret_request_by_info(
        &self,
        _secret_info: &SecretInfo,
    ) -> Result<Option<GossipRequest>> {
        // TODO
        Ok(None)
    }

    async fn get_unsent_secret_requests(&self) -> Result<Vec<GossipRequest>> {
        // TODO
        Ok(vec![])
    }

    async fn delete_outgoing_secret_requests(&self, _request_id: &TransactionId) -> Result<()> {
        // TODO
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use matrix_sdk_crypto::{store::CryptoStore, ReadOnlyAccount};
    use matrix_sdk_test::async_test;
    use once_cell::sync::Lazy;
    use ruma::{device_id, user_id, DeviceId, UserId};
    use tempfile::{tempdir, TempDir};

    use super::SanakirjaCryptoStore;

    //static TMP_DIR: Lazy<TempDir> = Lazy::new(|| tempdir().unwrap());

    async fn get_store(name: &str, passphrase: Option<&str>) -> SanakirjaCryptoStore {
        //let tmpdir_path = TMP_DIR.path().join(name);

        SanakirjaCryptoStore::open(/* tmpdir_path.to_str().unwrap(), */ passphrase).unwrap()
    }

    fn alice_id() -> &'static UserId {
        user_id!("@alice:example.org")
    }

    fn alice_device_id() -> &'static DeviceId {
        device_id!("ALICEDEVICE")
    }

    fn get_account() -> ReadOnlyAccount {
        ReadOnlyAccount::new(alice_id(), alice_device_id())
    }

    #[async_test]
    async fn save_account_via_generic_save() {
        let store = get_store("save_account_via_generic", None).await;
        assert!(store.load_account().await.unwrap().is_none());
        let account = get_account();

        store.save_account(account).await.expect("Can't save account");

        assert!(store.load_account().await.unwrap().is_none());
    }
}

#[cfg(test)]
mod encrypted_tests {
    use matrix_sdk_crypto::{store::CryptoStore, ReadOnlyAccount};
    use matrix_sdk_test::async_test;
    use once_cell::sync::Lazy;
    use ruma::{device_id, user_id, DeviceId, UserId};
    use tempfile::{tempdir, TempDir};

    use super::SanakirjaCryptoStore;

    //static TMP_DIR: Lazy<TempDir> = Lazy::new(|| tempdir().unwrap());

    async fn get_store(name: &str, passphrase: Option<&str>) -> SanakirjaCryptoStore {
        //let tmpdir_path = TMP_DIR.path().join(name);
        let pass = passphrase.unwrap_or("default_test_password");

        SanakirjaCryptoStore::open(/* tmpdir_path.to_str().unwrap(), */ Some(pass)).unwrap()
    }

    fn alice_id() -> &'static UserId {
        user_id!("@alice:example.org")
    }

    fn alice_device_id() -> &'static DeviceId {
        device_id!("ALICEDEVICE")
    }

    fn get_account() -> ReadOnlyAccount {
        ReadOnlyAccount::new(alice_id(), alice_device_id())
    }

    #[async_test]
    async fn save_account_via_generic_save() {
        let store = get_store("save_account_via_generic", None).await;
        assert!(store.load_account().await.unwrap().is_none());
        let account = get_account();

        store.save_account(account).await.expect("Can't save account");

        assert!(store.load_account().await.unwrap().is_none());
    }
}
