//! A generic interface to a signer.

use std::fmt;
use super::keys::{PublicKey, PublicKeyFormat};
use super::RpkiSignature;


//------------ Signer --------------------------------------------------------

/// A type that allow creating signatures.
pub trait Signer {
    /// The type used for identifying keys.
    type KeyId;

    /// An operational error happened in the signer.
    type Error: fmt::Debug + fmt::Display;

    /// Creates a new key and returns an identifier.
    fn create_key(
        &self
    ) -> Result<Self::KeyId, Self::Error>;

    /// Returns the public key information for the given key.
    ///
    /// If the key identified by `key` does not exist, returns `None`.
    fn get_key_info(
        &self,
        key: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>>;

    /// Destroys a key.
    ///
    /// Returns whether the key identified by `key` existed.
    fn destroy_key(
        &self,
        key: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>>;

    /// Signs data.
    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        data: &D
    ) -> Result<RpkiSignature, SigningError<Self::Error>>;

    /// Signs data using a one time use keypair.
    ///
    /// Returns both the signature and the public key of the key pair,
    /// but will not store this key pair.
    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        data: &D
    ) -> Result<(RpkiSignature, PublicKey), Self::Error>;

    /// Creates random data.
    ///
    /// The method fills the provide bytes slice with random data.
    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error>;
}


//------------ SigningAlgorithm ----------------------------------------------

/// The algorithm to use for signing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SigningAlgorithm {
    /// RSA with PKCS#1 1.5 padding using SHA-256.
    RsaSha256,

    /// ML-DSA-65 in 'pure mode'.
    MlDsa65,

    /// FN-DSA-512.
    FnDsa512,

    /// ECDSA using the P-256 curva and SHA-256.
    EcdsaP256Sha256,
}

impl SigningAlgorithm {
    /// Returns the preferred public key format for this algorithm.
    pub fn public_key_format(self) -> PublicKeyFormat {
        match self {
            SigningAlgorithm::RsaSha256 => PublicKeyFormat::Rsa,
            SigningAlgorithm::MlDsa65 => PublicKeyFormat::MlDsa65,
            SigningAlgorithm::FnDsa512 => PublicKeyFormat::FnDsa512,
            SigningAlgorithm::EcdsaP256Sha256 => PublicKeyFormat::EcdsaP256,
        }
    }
}


//------------ KeyError ------------------------------------------------------

#[derive(Clone, Debug)]
pub enum KeyError<S> {
    /// A key with the given key ID doesn’t exist.
    KeyNotFound,

    /// An error happened during signing.
    Signer(S)
}

impl<S> From<S> for KeyError<S> {
    fn from(err: S) -> Self {
        KeyError::Signer(err)
    }
}

impl<S: fmt::Display> fmt::Display for KeyError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::KeyError::*;

        match *self {
            KeyNotFound => write!(f, "key not found"),
            Signer(ref s) => s.fmt(f)
        }
    }
}


//------------ SigningError --------------------------------------------------

#[derive(Clone, Debug)]
pub enum SigningError<S> {
    /// A key with the given key ID doesn’t exist.
    KeyNotFound,

    /// The key cannot be used with the algorithm.
    IncompatibleKey,

    /// An error happened during signing.
    Signer(S)
}

impl<S> From<S> for SigningError<S> {
    fn from(err: S) -> Self {
        SigningError::Signer(err)
    }
}

impl<S> From<KeyError<S>> for SigningError<S> {
    fn from(err: KeyError<S>) -> Self {
        match err {
            KeyError::KeyNotFound => SigningError::KeyNotFound,
            KeyError::Signer(err) => SigningError::Signer(err)
        }
    }
}

impl<S: fmt::Display> fmt::Display for SigningError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SigningError::*;

        match *self {
            KeyNotFound => write!(f, "key not found"),
            IncompatibleKey => write!(f, "key not compatible with algorithm"),
            Signer(ref s) => s.fmt(f)
        }
    }
}

