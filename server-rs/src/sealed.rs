//! Sealed sender certificates, issued with libsignal itself (the Go server re-implements
//! XEdDSA and the protobuf encoding by hand).
//!
//! Keys are derived from the server secret exactly like the Go server, so both produce the
//! same trust root for the same CHATAPP_SERVER_SECRET.

use hmac::{Hmac, Mac};
use libsignal_protocol::{
    DeviceId, PrivateKey, PublicKey, SenderCertificate, ServerCertificate, Timestamp,
};
use sha2::Sha256;

/// Identifies the signing key inside sender certificates.
pub const SERVER_KEY_ID: u32 = 1;

fn derive_private_key(secret: &str, label: &str) -> PrivateKey {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(format!("chatapp/sealed-sender/{label}").as_bytes());
    let mut seed: [u8; 32] = mac.finalize().into_bytes().into();
    // Clamp like libsignal stores Curve25519 private keys.
    seed[0] &= 248;
    seed[31] &= 127;
    seed[31] |= 64;
    PrivateKey::deserialize(&seed).expect("32-byte private key")
}

pub struct Issuer {
    pub trust_root_public: PublicKey,
    server_key: PrivateKey,
    server_cert: ServerCertificate,
}

impl Issuer {
    pub fn new(secret: &str) -> Result<Issuer, String> {
        let root = derive_private_key(secret, "trust-root");
        let key = derive_private_key(secret, "server-key");
        let key_public = key.public_key().map_err(|e| e.to_string())?;
        let server_cert =
            ServerCertificate::new(SERVER_KEY_ID, key_public, &root, &mut rand::rng())
                .map_err(|e| e.to_string())?;
        Ok(Issuer {
            trust_root_public: root.public_key().map_err(|e| e.to_string())?,
            server_key: key,
            server_cert,
        })
    }

    /// Trust root in libsignal's serialization (type byte + 32 bytes), published in /v1/info.
    pub fn trust_root_serialized(&self) -> Vec<u8> {
        self.trust_root_public.serialize().to_vec()
    }

    /// Certifies that the account's device owns `identity_key` (libsignal serialization,
    /// 33 bytes) until `expires_ms`.
    pub fn sender_certificate(
        &self,
        account_id: &str,
        device: i64,
        identity_key: &[u8],
        expires_ms: i64,
    ) -> Result<Vec<u8>, String> {
        let key = PublicKey::deserialize(identity_key).map_err(|e| e.to_string())?;
        let device = DeviceId::new(u8::try_from(device).map_err(|_| "device id out of range")?)
            .map_err(|e| format!("{e:?}"))?;
        let cert = SenderCertificate::new(
            account_id.to_string(),
            None,
            key,
            device,
            Timestamp::from_epoch_millis(expires_ms.max(0) as u64),
            self.server_cert.clone(),
            &self.server_key,
            &mut rand::rng(),
        )
        .map_err(|e| e.to_string())?;
        Ok(cert.serialized().map_err(|e| e.to_string())?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_validates_against_trust_root() {
        let issuer = Issuer::new("0123456789abcdef0123456789abcdef").unwrap();
        let identity = libsignal_protocol::KeyPair::generate(&mut rand::rng());
        let id = "6f1c2a7e-0000-4000-8000-000000000001";
        let bytes = issuer
            .sender_certificate(
                id,
                2,
                &identity.public_key.serialize(),
                crate::now_millis() + 3_600_000,
            )
            .unwrap();
        let cert = SenderCertificate::deserialize(&bytes).unwrap();
        assert!(cert
            .validate(
                &issuer.trust_root_public,
                Timestamp::from_epoch_millis(crate::now_millis() as u64)
            )
            .unwrap());
        assert_eq!(cert.sender_uuid().unwrap(), id);
        // Same secret, same trust root (compatible with the Go server).
        assert_eq!(
            Issuer::new("0123456789abcdef0123456789abcdef")
                .unwrap()
                .trust_root_serialized(),
            issuer.trust_root_serialized()
        );
    }
}
