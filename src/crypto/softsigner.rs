//! A signer atop the OpenSSL library.
//!
//! Because this adds a dependency to openssl libs this is disabled by
//! default and should only be used by implementations that need to use
//! software keys to sign things, such as an RPKI Certificate Authority or
//! Publication Server. In particular, this is not required when validating.

use std::io;
use std::sync::{Arc, RwLock};
use bcder::decode::IntoSource;
use openssl::rsa::Rsa;
use openssl::pkey::{PKey, Private};
use openssl::hash::MessageDigest;
use ring::rand;
use ring::rand::SecureRandom;
use super::keys::{PublicKey, PublicKeyFormat};
use super::signer::{KeyError, Signer, SigningError};
use super::signature::Signature;
use super::{RpkiSignature, RpkiSignatureAlgorithm};



//------------ OQSSigner -------------------------------------------------

pub struct OQSSigner {
    keys: RwLock<Vec<Option<Arc<OQSKeyPair>>>>,
    rng: rand::SystemRandom,

}

struct OQSKeyPair {
    algorithm: PublicKeyFormat,
    pkey: oqs::sig::PublicKey,
    skey: oqs::sig::SecretKey,
}

// TODO: move OQS to separate crate
impl OQSKeyPair {
    fn new(algorithm: PublicKeyFormat) -> Result<Self, oqs::Error> {
        match algorithm {
            PublicKeyFormat::FnDsa512 => {
                let sigalg = oqs::sig::Sig::new(oqs::sig::Algorithm::Falcon512)?;
                let (pkey, skey) = sigalg.keypair()?;
                Ok(OQSKeyPair { pkey, skey, algorithm })
            }
            PublicKeyFormat::MlDsa65 => {
                let sigalg = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65)?;
                let (pkey, skey) = sigalg.keypair()?;
                Ok(OQSKeyPair { pkey, skey, algorithm })
            }
            _ => Err(oqs::Error::AlgorithmDisabled)
        }
        
    }

    fn sign(
        &self,
        data: &[u8]
    ) -> Result<RpkiSignature, oqs::Error> {
        let alg = match self.algorithm {
            PublicKeyFormat::FnDsa512 => oqs::sig::Algorithm::Falcon512,
            PublicKeyFormat::MlDsa65 => oqs::sig::Algorithm::MlDsa65,
            _ => return Err(oqs::Error::AlgorithmDisabled)
        };
        let sigalg = oqs::sig::Sig::new(alg)?;
        let sig = sigalg.sign(data, &self.skey)?;
        Ok(Signature::new(match self.algorithm {
            PublicKeyFormat::FnDsa512 => RpkiSignatureAlgorithm::FnDsa512,
            PublicKeyFormat::MlDsa65 => RpkiSignatureAlgorithm::MlDsa65,
            _ => unreachable!()
        }, sig.into_vec().into()))
    }

    fn get_key_info(&self) -> Result<PublicKey, oqs::Error> {
        match self.algorithm {
            PublicKeyFormat::FnDsa512 => {
                Ok(PublicKey::fndsa512_from_bytes(self.pkey.clone().into_vec().into()))
            }
            PublicKeyFormat::MlDsa65 => {
                Ok(PublicKey::mldsa65_from_bytes(self.pkey.clone().into_vec().into()))
            }
            _ => Err(oqs::Error::AlgorithmDisabled)
        }
    }
}

impl OQSSigner {
    pub fn new() -> OQSSigner {
        OQSSigner {
            keys: Default::default(),
            rng: rand::SystemRandom::new(),
        }
    }

    fn insert_key(&self, key: OQSKeyPair) -> KeyId {
        let mut keys = self.keys.write().unwrap();
        let res = keys.len();
        keys.push(Some(key.into()));
        KeyId(res)
    }

    fn get_key(&self, id: KeyId) -> Result<Arc<OQSKeyPair>, KeyError<oqs::Error>> {
        self.keys.read().unwrap().get(id.0).and_then(|key| {
            key.as_ref().cloned()
        }).ok_or(KeyError::KeyNotFound)
    }

    fn delete_key(&self, key: KeyId) -> Result<(), KeyError<oqs::Error>> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key.0);
        match key {
            Some(key) => {
                if key.is_some() {
                    *key = None;
                    Ok(())
                }
                else {
                    Err(KeyError::KeyNotFound)
                }
            }
            None => Err(KeyError::KeyNotFound)
        }
    }
}

impl Signer for OQSSigner {
    type KeyId = KeyId;
    type Error = oqs::Error;

    fn create_key(
        &self,
    ) -> Result<Self::KeyId, Self::Error> {
        Ok(self.insert_key(OQSKeyPair::new(PublicKeyFormat::FnDsa512)?))   
    }

    fn get_key_info(
        &self,
        id: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>> {
        self.get_key(*id)?.get_key_info().map_err(KeyError::Signer)
    }

    fn destroy_key(
        &self, key: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>> {
        self.delete_key(*key)
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        data: &D
    ) -> Result<RpkiSignature, SigningError<Self::Error>> {
        self.get_key(*key)?.sign(data.as_ref()).map_err(Into::into)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        data: &D
    ) -> Result<(RpkiSignature, PublicKey), Self::Error> {
        let key = OQSKeyPair::new(PublicKeyFormat::FnDsa512)?;
        let info = key.get_key_info()?;
        let sig = key.sign(data.as_ref())?;
        Ok((sig, info))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill(target).map_err(|_|
            oqs::Error::Error
        )
    }
}


impl Default for OQSSigner {
    fn default() -> Self {
        Self::new()
    }
}

//------------ OpenSslSigner -------------------------------------------------

/// An OpenSSL based signer.
///
/// Keeps the keys in memory (for now).
pub struct OpenSslSigner {
    keys: RwLock<Vec<Option<Arc<KeyPair>>>>,
    rng: rand::SystemRandom,
}

impl OpenSslSigner {
    pub fn new() -> OpenSslSigner {
        OpenSslSigner {
            keys: Default::default(),
            rng: rand::SystemRandom::new(),
        }
    }

    pub fn key_from_der(&self, der: &[u8]) -> Result<KeyId, io::Error> {
        Ok(self.insert_key(KeyPair::from_der(der)?))
    }

    pub fn key_from_pem(&self, pem: &[u8]) -> Result<KeyId, io::Error> {
        Ok(self.insert_key(KeyPair::from_pem(pem)?))
    }

    fn insert_key(&self, key: KeyPair) -> KeyId {
        let mut keys = self.keys.write().unwrap();
        let res = keys.len();
        keys.push(Some(key.into()));
        KeyId(res)
    }

    fn get_key(&self, id: KeyId) -> Result<Arc<KeyPair>, KeyError<io::Error>> {
        self.keys.read().unwrap().get(id.0).and_then(|key| {
            key.as_ref().cloned()
        }).ok_or(KeyError::KeyNotFound)
    }

    fn delete_key(&self, key: KeyId) -> Result<(), KeyError<io::Error>> {
        let mut keys = self.keys.write().unwrap();
        let key = keys.get_mut(key.0);
        match key {
            Some(key) => {
                if key.is_some() {
                    *key = None;
                    Ok(())
                }
                else {
                    Err(KeyError::KeyNotFound)
                }
            }
            None => Err(KeyError::KeyNotFound)
        }
    }
}

impl Signer for OpenSslSigner {
    type KeyId = KeyId;
    type Error = io::Error;

    fn create_key(
        &self,
    ) -> Result<Self::KeyId, Self::Error> {
        Ok(self.insert_key(KeyPair::new(PublicKeyFormat::Rsa)?))
    }

    fn get_key_info(
        &self,
        id: &Self::KeyId
    ) -> Result<PublicKey, KeyError<Self::Error>> {
        self.get_key(*id)?.get_key_info().map_err(KeyError::Signer)
    }

    fn destroy_key(
        &self, key: &Self::KeyId
    ) -> Result<(), KeyError<Self::Error>> {
        self.delete_key(*key)
    }

    fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key: &Self::KeyId,
        data: &D
    ) -> Result<RpkiSignature, SigningError<Self::Error>> {
        self.get_key(*key)?.sign(data.as_ref()).map_err(Into::into)
    }

    fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        data: &D
    ) -> Result<(RpkiSignature, PublicKey), Self::Error> {
        let key = KeyPair::new(PublicKeyFormat::Rsa)?;
        let info = key.get_key_info()?;
        let sig = key.sign(data.as_ref())?;
        Ok((sig, info))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill(target).map_err(|_|
            io::Error::new(io::ErrorKind::Other, "rng error")
        )
    }
}


impl Default for OpenSslSigner {
    fn default() -> Self {
        Self::new()
    }
}


//------------ KeyId ---------------------------------------------------------

/// This signer’s key identifier.
//
//  We wrap this in a newtype so that people won’t start mucking about with
//  the integers.
#[derive(Clone, Copy, Debug)]
pub struct KeyId(usize);


//------------ KeyPair -------------------------------------------------------

/// A key pair kept by the signer.
struct KeyPair(PKey<Private>);

impl KeyPair {
    fn new(algorithm: PublicKeyFormat) -> Result<Self, io::Error> {
        if algorithm != PublicKeyFormat::Rsa {
            return Err(io::Error::new(
                io::ErrorKind::Other, "invalid algorithm"
            ));
        }
        // Issues unwrapping this indicate a bug in the openssl library.
        // So, there is no way to recover.
        let rsa = Rsa::generate(2048)?;
        let pkey = PKey::from_rsa(rsa)?;
        Ok(KeyPair(pkey))
    }

    fn from_der(der: &[u8]) -> Result<Self, io::Error> {
        let res = PKey::private_key_from_der(der)?;
        if res.bits() != 2048 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("invalid key length {}", res.bits())
            ))
        }
        Ok(KeyPair(res))
    }

    fn from_pem(pem: &[u8]) -> Result<Self, io::Error> {
        let res = PKey::private_key_from_pem(pem)?;
        if res.bits() != 2048 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("invalid key length {}", res.bits())
            ))
        }
        Ok(KeyPair(res))
    }

    fn get_key_info(&self) -> Result<PublicKey, io::Error>
    {
        // Issues unwrapping this indicate a bug in the openssl
        // library. So, there is no way to recover.
        let der = self.0.rsa().unwrap().public_key_to_der()?;
        Ok(PublicKey::decode(der.as_slice().into_source()).unwrap())
    }

    fn sign(
        &self,
        data: &[u8]
    ) -> Result<RpkiSignature, io::Error> {
        let mut signer = ::openssl::sign::Signer::new(
            MessageDigest::sha256(), &self.0
        )?;
        signer.update(data)?;
        Ok(Signature::new(RpkiSignatureAlgorithm::default(), signer.sign_to_vec()?.into()))
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn info_sign_delete() {
        let s = OpenSslSigner::new();
        let ki = s.create_key().unwrap();
        let data = b"foobar";
        let _ = s.get_key_info(&ki).unwrap();
        let _ = s.sign(&ki, data).unwrap();
        s.destroy_key(&ki).unwrap();
    }
    
    #[test]
    fn one_off() {
        let s = OpenSslSigner::new();
        s.sign_one_off(b"foobar").unwrap();
    }
}



#[cfg(test)]
pub mod pqc_tests {

    use super::*;

    #[test]
    fn create_sign_verify() {
        let s = OQSSigner::new();
        let ki = s.create_key().unwrap();
        let data = b"foobar";
        let pk = s.get_key_info(&ki).unwrap();
        let signature = s.sign(&ki, data).unwrap();
        pk.verify(b"foobar", &signature).unwrap();
        s.destroy_key(&ki).unwrap();
    }
    
    #[test]
    fn one_off() {
        let s = OQSSigner::new();
        s.sign_one_off(b"foobar").unwrap();
    }
}
