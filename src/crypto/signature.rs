//! Signature algorithms and operations.

use bcder::{decode, encode};
use bcder::{ConstOid, Oid, Tag};
use bcder::decode::DecodeError;
use bcder::encode::PrimitiveContent;
use bytes::Bytes;
use crate::oid;
use super::keys::PublicKeyFormat;
use super::signer::SigningAlgorithm;


//------------ SignatureAlgorithm --------------------------------------------

/// The allowed signature algorithms for a certain purpose.
pub trait SignatureAlgorithm: Sized {
    type Encoder: encode::Values;

    /// Returns the signing algorithm for this algorithm.
    fn signing_algorithm(&self) -> SigningAlgorithm;

    /// Returns the public key format for the algorithm.
    fn public_key_format(&self) -> PublicKeyFormat {
        self.signing_algorithm().public_key_format()
    }

    /// Takes the algorithm identifier from a DER value in X.509 signed data.
    fn x509_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>>;

    /// Returns a DER encoder.
    fn x509_encode(&self) -> Self::Encoder;
}


//------------ RpkiSignatureAlgorithm ----------------------------------------

/// A signature algorithms used by RPKI.
///
/// These are the algorithms used for creating and verifying signatures. For
/// RPKI, [RFC 7935] allows only one algorithm, RSA PKCS #1 v1.5 with
/// SHA-256. However, there are two possible representations of the
/// non-existant algorithm parameters. In certain circumstances, it is
/// imporant that these two representations do not compare as equal.
/// Therefore, this type keeps track of the representation used.
///
/// Should additional algorithms be introduced into RPKI, this type will be
/// adjusted accordingly.
///
/// You can construct the signature algorithm currently preferred for RPKI
/// via the `Default` implementation.
///
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RpkiSignatureAlgorithm {
    RsaSha256 {
        /// Is the parameter field present?
        ///
        /// If `true`, then a parameter field is present and NULL. Otherwise it
        /// is missing.
        ///
        /// Constructed values will always have this set to `true`.
        has_parameter: bool,
    },
    MlDsa65,
    FnDsa512,
}

/// # ASN.1 Values
///
/// Signature algorithm identifiers appear in certificates and other objects
/// from [RFC 5280] (simply as algorithm identifiers) as well as in signed
/// objects.
///
/// ```txt
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// AlgorithmIdentifier          ::= SEQUENCE {
///      algorithm                   OBJECT IDENTIFIER,
///      parameters                  ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// Currently, [RFC 7935] allows only one algorithm, but sadly it uses
/// different identifiers in different places. For X.509-related objects,
/// i.e., certificates, CRLs, and certification requests, this is
/// `sha256WithRSAEncryption` from [RFC 4055].  For signed objects, the
/// identifier must be `rsaEncryption` from [RFC 3370] for constructed
/// objects while both must be accepted when reading objects.
///
/// Because of these differences, you’ll find two sets of functions and
/// methods in this section. Those prefixed with `x509` deal with the
/// X.509-related identifiers while `cms_` is the prefix for signed objects.
///
/// The parameters field for the former identifier can be either NULL or
/// missing and must be NULL for the latter. We will, however, accept an
/// absent field for the latter as well. In both cases, the returned value
/// will remember whether there was a parameters field. Values with and
/// without parameters will not compare equal.
///
/// When constructing identifiers, we will always include a parameters field
/// and set it to NULL, independently of what the value says.
///
/// [RFC 3370]: https://tools.ietf.org/html/rfc3370
/// [RFC 4055]: https://tools.ietf.org/html/rfc4055
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
impl RpkiSignatureAlgorithm {
    /// Parses the algorithm identifier for X.509 objects.
    fn x509_from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let oid = Oid::take_from(cons)?;
        if oid == oid::SHA256_WITH_RSA_ENCRYPTION {
            let has_parameter = cons.take_opt_primitive_if(
                Tag::NULL, |_| Ok(())
            )?.is_some();
            Ok(RpkiSignatureAlgorithm::RsaSha256 { has_parameter } )
        } else if oid == oid::MLDSA65 {
            Ok(RpkiSignatureAlgorithm::MlDsa65)
        } else if oid == oid::FNDSA512 {
            // TODO: FN-DSA formats have not been made yet. This is simply copied form ML-DSA.
            Ok(RpkiSignatureAlgorithm::FnDsa512)        
        } else {
            Err(cons.content_err("invalid signature algorithm"))
        }
    }

    /// Takes a signature algorithm identifier for CMS objects.
    ///
    /// Returns a malformed error if the algorithm isn’t the allowed for RPKI
    /// or if it isn’t correctly encoded.
    pub fn cms_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::cms_from_constructed)
    }

    /// Parses the algorithm identifier for CMS objects.
    fn cms_from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        let oid = Oid::take_from(cons)?;

        if
            oid == oid::RSA_ENCRYPTION
            || oid == oid::SHA256_WITH_RSA_ENCRYPTION
        {
            let has_parameter = cons.take_opt_primitive_if(
                Tag::NULL, |_| Ok(())
            )?.is_some();
            Ok(RpkiSignatureAlgorithm::RsaSha256 { has_parameter })
        } else if oid == oid::MLDSA65 {
            // From the examples in [draft-ietf-lamps-cms-ml-dsa-02] and 
            // [draft-ietf-lamps-dilithium-certificates-07] it seems that
            // the parameter is consistently absent, not NULL.
            Ok(RpkiSignatureAlgorithm::MlDsa65)
        } else if oid == oid::FNDSA512 {
            // TODO: FN-DSA formats have not been made yet. This is simply copied from ML-DSA.
            Ok(RpkiSignatureAlgorithm::FnDsa512)        
        } else {
            Err(cons.content_err("invalid signature algorithm"))
        }
    }

    /// Provides an encoder for X.509 objects.
    /// 
    /// Returns a choice of very similar types that are not exactly the same because
    /// for ML-DSA we do not include a NULL parameter to match (the examples in)
    /// [draft-ietf-lamps-cms-ml-dsa-02] and [draft-ietf-lamps-dilithium-certificates-07].
    pub fn x509_encode(&self) -> impl encode::Values {
        match self {
            RpkiSignatureAlgorithm::RsaSha256 { .. } => encode::Choice2::One(encode::sequence((
                oid::SHA256_WITH_RSA_ENCRYPTION.encode(),
                ().encode(),
            ))),
            RpkiSignatureAlgorithm::MlDsa65 => encode::Choice2::Two(encode::sequence((
                oid::MLDSA65.encode(),
            ))),
            RpkiSignatureAlgorithm::FnDsa512 => encode::Choice2::Two(encode::sequence((
                oid::FNDSA512.encode(),
            ))),
        }
    }

    /// Provides an encoder for CMS objects.
    /// 
    /// Returns a choice of very similar types that are not exactly the same because
    /// for ML-DSA we do not include a NULL parameter to match (the examples in)
    /// [draft-ietf-lamps-cms-ml-dsa-02] and [draft-ietf-lamps-dilithium-certificates-07].
    pub fn cms_encode(&self) -> impl encode::Values {
        match self {
            RpkiSignatureAlgorithm::RsaSha256 { .. } => encode::Choice2::One(encode::sequence((
                oid::RSA_ENCRYPTION.encode(),
                ().encode(),
            ))),
            RpkiSignatureAlgorithm::MlDsa65 => encode::Choice2::Two(encode::sequence((
                oid::MLDSA65.encode(),
            ))),
            RpkiSignatureAlgorithm::FnDsa512 => encode::Choice2::Two(encode::sequence((
                oid::FNDSA512.encode(),
            ))),
        }
    }
}


//--- Default

impl Default for RpkiSignatureAlgorithm {
    fn default() -> Self {
        RpkiSignatureAlgorithm::RsaSha256 { has_parameter: true }
    }
}


//--- SignatureAlgorithm

impl SignatureAlgorithm for RpkiSignatureAlgorithm {
    type Encoder = encode::Choice2<
        encode::Constructed<(encode::Primitive<ConstOid>, encode::Primitive<()>)>, 
        encode::Constructed<(encode::Primitive<ConstOid>,)>,
    >;

    fn signing_algorithm(&self) -> SigningAlgorithm {
        match *self {
            RpkiSignatureAlgorithm::RsaSha256 { .. } => SigningAlgorithm::RsaSha256,
            RpkiSignatureAlgorithm::MlDsa65 => SigningAlgorithm::MlDsa65,
            RpkiSignatureAlgorithm::FnDsa512 => SigningAlgorithm::FnDsa512,
        }
    }

    fn x509_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::x509_from_constructed)
    }

    fn x509_encode(&self) -> Self::Encoder {
        match self {
            RpkiSignatureAlgorithm::RsaSha256 { .. } => encode::Choice2::One(
                encode::Constructed::new(
                    Tag::SEQUENCE, 
                    (oid::SHA256_WITH_RSA_ENCRYPTION.encode(), ().encode()),
                ),
            ),
            RpkiSignatureAlgorithm::MlDsa65 => encode::Choice2::Two(
                encode::Constructed::new( 
                    Tag::SEQUENCE, 
                    (oid::MLDSA65.encode(),),
                ),
            ),
            RpkiSignatureAlgorithm::FnDsa512 => encode::Choice2::Two(
                encode::Constructed::new(
                    Tag::SEQUENCE,
                    (oid::FNDSA512.encode(),),
                ),
            ),
        }
    }
}


//------------ BgpsecSignatureAlgorithm --------------------------------------

/// A signature algorithms used by BGPsec.
///
/// This is the algorithm used for creating and verifying signatures in
/// certification requests for router certificates. The allowed algorithms
/// are currently defined in [RFC 8608] as only ECDSA with curve P-256 and
/// SHA-256.
///
/// [RFC 8608]: https://tools.ietf.org/html/rfc8608
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BgpsecSignatureAlgorithm(());

impl BgpsecSignatureAlgorithm {
    /// Parses the algorithm identifier for X.509 objects.
    fn x509_from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        oid::ECDSA_WITH_SHA256.skip_if(cons)?;
        Ok(BgpsecSignatureAlgorithm(()))
    }
}

impl SignatureAlgorithm for BgpsecSignatureAlgorithm {
    type Encoder = encode::Constructed<encode::Primitive<ConstOid>>;

    fn signing_algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256Sha256
    }

    fn x509_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::x509_from_constructed)
    }

    fn x509_encode(&self) -> Self::Encoder {
        encode::Constructed::new(
            Tag::SEQUENCE,
            oid::ECDSA_WITH_SHA256.encode()
        )
    }
}


//------------ Signature -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature<Alg> {
    algorithm: Alg,
    value: Bytes
}

pub type RpkiSignature = Signature<RpkiSignatureAlgorithm>;

impl<Alg> Signature<Alg> {
    pub fn new(algorithm: Alg, value: Bytes) -> Self {
        Signature { algorithm, value }
    }

    pub fn algorithm(&self) -> &Alg {
        &self.algorithm
    }

    pub fn value(&self) -> &Bytes {
        &self.value
    }

    pub fn unwrap(self) -> (Alg, Bytes) {
        (self.algorithm, self.value)
    }
}

pub fn verify_pq(
    public_key: untrusted::Input,
    msg: untrusted::Input,
    signature: untrusted::Input,
    algorithm: oqs::sig::Algorithm,
) -> Result<(), ()> {
    // This needs to happen once, but is safe to call multiple times
    // as it internally uses `std::sync::Once`.
    oqs::init();

    let sigalg = oqs::sig::Sig::new(algorithm).map_err(|_| ())?;
    let pk = sigalg
        .public_key_from_bytes(public_key.as_slice_less_safe())
        .ok_or(())?;
    let sig = sigalg
        .signature_from_bytes(signature.as_slice_less_safe())
        .ok_or(())?;

    sigalg
        .verify(msg.as_slice_less_safe(), sig, pk)
        .map_err(|_| ())?;
    Ok(())
}
