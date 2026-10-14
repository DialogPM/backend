//! zkgroup server parameters (docs/ZKGROUP-DESIGN.md).
//!
//! The secret parameters are derived from CHATAPP_SERVER_SECRET (like the sealed sender keys),
//! so every instance of a server agrees on them without extra storage.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zkgroup::auth::AuthCredentialWithPniZkcResponse;
use zkgroup::{ServerPublicParams, ServerSecretParams, Timestamp, RANDOMNESS_LEN, SECONDS_PER_DAY};

/// Salt for the "false PNI" of auth credentials: accounts have no phone-number identity.
pub const PNI_SALT: &[u8] = b"chatapp/zkgroup/no-pni";
/// How many days of credentials a client may fetch at once.
pub const MAX_CREDENTIAL_DAYS: u64 = 7;

pub struct ZkParams {
    pub secret: ServerSecretParams,
    pub public: ServerPublicParams,
    pub public_serialized: Vec<u8>,
}

fn derive(secret: &str, label: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(format!("chatapp/zkgroup/{label}").as_bytes());
    mac.finalize().into_bytes().into()
}

fn randomness() -> [u8; RANDOMNESS_LEN] {
    use rand::RngCore;
    let mut r = [0u8; RANDOMNESS_LEN];
    rand::rng().fill_bytes(&mut r);
    r
}

impl ZkParams {
    pub fn new(server_secret: &str) -> ZkParams {
        let secret = ServerSecretParams::generate(derive(server_secret, "server-params"));
        let public = secret.get_public_params();
        let public_serialized = zkgroup::serialize(&public);
        ZkParams { secret, public, public_serialized }
    }

    /// Auth credential of `account` for the day starting at `day_start` (UTC seconds).
    pub fn auth_credential(&self, account: uuid::Uuid, day_start: u64) -> Vec<u8> {
        let resp = AuthCredentialWithPniZkcResponse::issue_credential_without_pni(
            libsignal_core::Aci::from(account),
            PNI_SALT,
            Timestamp::from_epoch_seconds(day_start),
            &self.secret,
            randomness(),
        );
        zkgroup::serialize(&resp)
    }
}

/// Context of the server's signature over a private group change (clients verify it with the
/// pinned public parameters): context || group identifier || change bytes.
pub const GROUP_CHANGE_CONTEXT: &[u8] = b"chatapp/group-v2/change\0";

impl ZkParams {
    /// Notary signature over a group change (docs/ZKGROUP-DESIGN.md stage 2).
    pub fn sign_group_change(&self, group_id: &[u8], change: &[u8]) -> [u8; 64] {
        let mut msg = Vec::with_capacity(GROUP_CHANGE_CONTEXT.len() + group_id.len() + change.len());
        msg.extend_from_slice(GROUP_CHANGE_CONTEXT);
        msg.extend_from_slice(group_id);
        msg.extend_from_slice(change);
        self.secret.sign(randomness(), &msg)
    }
}

/// Whether `t` is a valid redemption day start.
pub fn day_aligned(t: u64) -> bool {
    t % SECONDS_PER_DAY == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkgroup::auth::AnyAuthCredentialPresentation;
    use zkgroup::groups::GroupSecretParams;

    /// Full cycle: issue -> receive (client) -> present for a group -> verify (server).
    #[test]
    fn credential_roundtrip() {
        let zk = ZkParams::new("0123456789abcdef0123456789abcdef");
        let account = uuid::Uuid::new_v4();
        let now = crate::now_millis() as u64 / 1000;
        let day = now - now % SECONDS_PER_DAY;
        let bytes = zk.auth_credential(account, day);

        // Client side.
        let public: ServerPublicParams = zkgroup::deserialize(&zk.public_serialized).unwrap();
        let resp: AuthCredentialWithPniZkcResponse = zkgroup::deserialize(&bytes).unwrap();
        let aci = libsignal_core::Aci::from(account);
        let cred = resp.receive_without_pni(aci, PNI_SALT, Timestamp::from_epoch_seconds(day), &public).unwrap();
        let group = GroupSecretParams::generate(randomness());
        let presentation = zkgroup::serialize(&cred.present(&public, &group, randomness()));

        // Server side: verifies without learning the account, gets its ciphertext.
        let p = AnyAuthCredentialPresentation::new(&presentation).unwrap();
        zk.secret
            .verify_auth_credential_presentation(group.get_public_params(), &p, Timestamp::from_epoch_seconds(now))
            .unwrap();
        assert!(zkgroup::serialize(&p.get_aci_ciphertext()) == zkgroup::serialize(&group.encrypt_service_id(aci.into())));

        // Another group's params do not verify, and the same secret gives the same params.
        let other = GroupSecretParams::generate(randomness());
        assert!(zk.secret.verify_auth_credential_presentation(other.get_public_params(), &p, Timestamp::from_epoch_seconds(now)).is_err());
        assert_eq!(ZkParams::new("0123456789abcdef0123456789abcdef").public_serialized, zk.public_serialized);
    }
}
