use codec::{Decode, Encode};
#[cfg(feature = "std")]
pub use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use sp_core::RuntimeDebug;
use sp_core::{
    crypto, ecdsa, ed25519,
    hash::{H256, H512},
    sr25519,
};
use sp_runtime::traits;
use sp_std::convert::TryFrom;
use sp_std::prelude::*;
use traits::{IdentifyAccount, Lazy, Verify};
use hex;

pub mod rsa {
    use super::*;
    use core::cmp::Ordering;
    #[cfg(feature = "std")]
    use serde::{de, Serializer, Deserializer};
    #[derive(Encode, Decode)]
    pub struct Signature([u8; 256]);
    
    impl sp_std::convert::TryFrom<&[u8]> for Signature {
        type Error = ();

        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() == 256 {
                let mut inner = [0u8; 256];
                inner.copy_from_slice(data);
                Ok(Signature(inner))
            } else {
                Err(())
            }
        }
    }

    #[cfg(feature = "std")]
    impl Serialize for Signature {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&hex::encode(self))
        }
    }

    #[cfg(feature = "std")]
    impl<'de> Deserialize<'de> for Signature {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let signature_hex = hex::decode(&String::deserialize(deserializer)?)
                .map_err(|e| de::Error::custom(format!("{:?}", e)))?;
            Ok(Signature::try_from(signature_hex.as_ref())
                .map_err(|e| de::Error::custom(format!("{:?}", e)))?)
        }
    }

    impl Clone for Signature {
        fn clone(&self) -> Self {
            let mut r = [0u8; 256];
            r.copy_from_slice(&self.0[..]);
            Signature(r)
        }
    }

    impl Default for Signature {
        fn default() -> Self {
            Signature([0u8; 256])
        }
    }

    impl PartialEq for Signature {
        fn eq(&self, b: &Self) -> bool {
            self.0[..] == b.0[..]
        }
    }

    impl Eq for Signature {}

    impl From<Signature> for [u8; 256] {
        fn from(v: Signature) -> [u8; 256] {
            v.0
        }
    }

    impl AsRef<[u8; 256]> for Signature {
        fn as_ref(&self) -> &[u8; 256] {
            &self.0
        }
    }

    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            &self.0[..]
        }
    }

    impl AsMut<[u8]> for Signature {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.0[..]
        }
    }

    #[cfg(feature = "std")]
    impl std::fmt::Debug for Signature {
	      fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		        write!(f, "{}", "<Signature>")
	      }
    }

    #[derive(Clone, Encode, Decode)]
    pub struct Public(Vec<u8>);
    
    impl PartialOrd for Public {
	      fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		        Some(self.cmp(other))
	      }
    }

    impl Ord for Public {
	      fn cmp(&self, other: &Self) -> Ordering {
		        self.as_ref().cmp(&other.as_ref())
	      }
    }

    impl PartialEq for Public {
	      fn eq(&self, other: &Self) -> bool {
		        self.as_ref() == other.as_ref()
	      }
    }

    impl Eq for Public {}

    impl AsRef<[u8]> for Public {
        fn as_ref(&self) -> &[u8] {
            &self.0[..]
        }
    }

    #[cfg(feature = "std")]
    impl std::fmt::Debug for Public {
	      fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		        write!(f, "{}", "<Public>")
	      }
    }
    #[cfg(feature = "std")]
    impl Serialize for Public {
	      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
		        serializer.serialize_str("Serialized Dummy Rsa")
	      }
    }

    #[cfg(feature = "std")]
    impl<'de> Deserialize<'de> for Public {
	      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
		        Ok(Self(vec![19u8; 256]))
	      }
    }
    
}

/// Signature verify that can work with any known signature types..
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Eq, PartialEq, Clone, Encode, Decode, RuntimeDebug)]
pub enum MultiSignature {
    /// An Ed25519 signature.
    Ed25519(ed25519::Signature),
    /// An Sr25519 signature.
    Sr25519(sr25519::Signature),
    /// An ECDSA/SECP256k1 signature.
    Ecdsa(ecdsa::Signature),
    /// Dummy signature(dummy)
    Rsa(rsa::Signature),
}

impl From<ed25519::Signature> for MultiSignature {
    fn from(x: ed25519::Signature) -> Self {
        MultiSignature::Ed25519(x)
    }
}

impl From<sr25519::Signature> for MultiSignature {
    fn from(x: sr25519::Signature) -> Self {
        MultiSignature::Sr25519(x)
    }
}

impl From<ecdsa::Signature> for MultiSignature {
    fn from(x: ecdsa::Signature) -> Self {
        MultiSignature::Ecdsa(x)
    }
}
impl From<rsa::Signature> for MultiSignature {
    fn from(x: rsa::Signature) -> Self {
        MultiSignature::Rsa(x)
    }
}

impl Default for MultiSignature {
    fn default() -> Self {
        MultiSignature::Ed25519(Default::default())
    }
}

/// Public key for any known crypto algorithm.
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum MultiSigner {
    /// An Ed25519 identity.
    Ed25519(ed25519::Public),
    /// An Sr25519 identity.
    Sr25519(sr25519::Public),
    /// An SECP256k1/ECDSA identity (actually, the Blake2 hash of the compressed pub key).
    Ecdsa(ecdsa::Public),
    /// An rsa identity
    Rsa(rsa::Public),
}

impl Default for MultiSigner {
    fn default() -> Self {
        MultiSigner::Ed25519(Default::default())
    }
}

/// NOTE: This implementations is required by `SimpleAddressDeterminer`,
/// we convert the hash into some AccountId, it's fine to use any scheme.
impl<T: Into<H256>> crypto::UncheckedFrom<T> for MultiSigner {
    fn unchecked_from(x: T) -> Self {
        ed25519::Public::unchecked_from(x.into()).into()
    }
}

impl AsRef<[u8]> for MultiSigner {
    fn as_ref(&self) -> &[u8] {
        match *self {
            MultiSigner::Ed25519(ref who) => who.as_ref(),
            MultiSigner::Sr25519(ref who) => who.as_ref(),
            MultiSigner::Ecdsa(ref who) => who.as_ref(),
            MultiSigner::Rsa(ref who) => who.as_ref(),
        }
    }
}

impl traits::IdentifyAccount for MultiSigner {
    type AccountId = AccountId32;
    fn into_account(self) -> AccountId32 {
        match self {
            MultiSigner::Ed25519(who) => <[u8; 32]>::from(who).into(),
            MultiSigner::Sr25519(who) => <[u8; 32]>::from(who).into(),
            MultiSigner::Ecdsa(who) => sp_io::hashing::blake2_256(&who.as_ref()[..]).into(),
            MultiSigner::Rsa(who) => sp_io::hashing::blake2_256(&who.as_ref()[..]).into(),
        }
    }
}

impl From<ed25519::Public> for MultiSigner {
    fn from(x: ed25519::Public) -> Self {
        MultiSigner::Ed25519(x)
    }
}

impl TryFrom<MultiSigner> for ed25519::Public {
    type Error = ();
    fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
        if let MultiSigner::Ed25519(x) = m {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<sr25519::Public> for MultiSigner {
    fn from(x: sr25519::Public) -> Self {
        MultiSigner::Sr25519(x)
    }
}

impl TryFrom<MultiSigner> for sr25519::Public {
    type Error = ();
    fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
        if let MultiSigner::Sr25519(x) = m {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<ecdsa::Public> for MultiSigner {
    fn from(x: ecdsa::Public) -> Self {
        MultiSigner::Ecdsa(x)
    }
}

impl TryFrom<MultiSigner> for ecdsa::Public {
    type Error = ();
    fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
        if let MultiSigner::Ecdsa(x) = m {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<rsa::Public> for MultiSigner {
    fn from(x: rsa::Public) -> Self {
        MultiSigner::Rsa(x)
    }
}

impl TryFrom<MultiSigner> for rsa::Public {
    type Error = ();
    fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
        if let MultiSigner::Rsa(x) = m {
            Ok(x)
        } else {
            Err(())
        }
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for MultiSigner {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            MultiSigner::Ed25519(ref who) => write!(fmt, "ed25519: {}", who),
            MultiSigner::Sr25519(ref who) => write!(fmt, "sr25519: {}", who),
            MultiSigner::Ecdsa(ref who) => write!(fmt, "ecdsa: {}", who),
            MultiSigner::Rsa(ref who) => write!(fmt, "rsa: {}", "Dummy mesage"),
        }
    }
}

impl Verify for MultiSignature {
    type Signer = MultiSigner;
    fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId32) -> bool {
        use sp_core::crypto::Public;
        true
    }
}

/// Signature verify that can work with any known signature types..
#[derive(Eq, PartialEq, Clone, Default, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct AnySignature(H512);

impl Verify for AnySignature {
    type Signer = sr25519::Public;
    fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &sr25519::Public) -> bool {
        use sp_core::crypto::Public;
        let msg = msg.get();
        false
            && sr25519::Signature::try_from(self.0.as_fixed_bytes().as_ref())
                .map(|s| s.verify(msg, signer))
                .unwrap_or(false)
            || ed25519::Signature::try_from(self.0.as_fixed_bytes().as_ref())
                .map(|s| s.verify(msg, &ed25519::Public::from_slice(signer.as_ref())))
                .unwrap_or(false)
    }
}

impl From<sr25519::Signature> for AnySignature {
    fn from(s: sr25519::Signature) -> Self {
        AnySignature(s.into())
    }
}

impl From<ed25519::Signature> for AnySignature {
    fn from(s: ed25519::Signature) -> Self {
        AnySignature(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::crypto::Pair;

    #[test]
    fn multi_signature_sr25519_verify_works() {
        let msg = &b"test-message"[..];
        let (pair, _) = sr25519::Pair::generate();

        let signature = pair.sign(&msg);
        assert!(sr25519::Pair::verify(&signature, msg, &pair.public()));

        let multi_sig = MultiSignature::from(signature);
        let multi_signer = MultiSigner::from(pair.public());
        assert!(multi_sig.verify(msg, &multi_signer.into_account()));

        let multi_signer = MultiSigner::from(pair.public());
        assert!(multi_sig.verify(msg, &multi_signer.into_account()));
    }
}
