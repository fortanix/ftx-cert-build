use pkix::types::DerSequence;

use crate::crypto_provider::PkProvider;
use crate::error::Result;

pub trait TbsKeys {
    /// DER-encoded SubjectPublicKeyInfo extension
    type Spki;
    type SigAlgorithm;

    /// We take a mutable borrow here since some keys write to their cache when extracting public keys
    fn spki(&mut self) -> Result<Self::Spki>;

    fn signature_algorithm(&self) -> Self::SigAlgorithm;
}

/// Make sure we do not need to consume a private key to pass it to a function that requires an
/// spki
impl<T: TbsKeys> TbsKeys for &mut T {
    type Spki = <T as TbsKeys>::Spki;
    type SigAlgorithm = <T as TbsKeys>::SigAlgorithm;

    fn spki(&mut self) -> Result<Self::Spki> {
        (*self).spki()
    }

    fn signature_algorithm(&self) -> Self::SigAlgorithm {
        (**self).signature_algorithm()
    }
}

pub trait CertificateKeys: TbsKeys {
    type Pk;

    fn private_key(&mut self) -> &mut Self::Pk;

    fn is_self_signed(&self) -> bool {
        false
    }
}

/// State where no key material is configured yet and building will be impossible.
#[derive(Clone, Debug)]
pub struct NoKeyMaterial;

/// State where default key material for self-signing will be generated.
///
/// Contains a reference to the `PK` type that should be generated.
pub struct DefaultSelfSigningKeyMaterial<A>(pub(crate) A);

/// State represented by a public key (without private key) and a signature algorithm.
#[derive(Debug)]
pub struct SpkiKeyMaterial<'a, A> {
    pub(crate) spki: &'a [u8],

    /// The signature algorithm that the tbs will list and that should be used when signing the tbs.
    pub(crate) signature_algorithm: A,
}

/// State that allows self-signing through a public-private key pair.
pub struct SelfSigningKeyMaterial<'a, PK, A> {
    pub(crate) signing_key: &'a mut PK,

    /// The signature algorithm that the tbs will list and that will be used when signing the tbs.
    pub(crate) signature_algorithm: A,
}

/// State that allows generating a signed certificate using the given public and private keys.
pub struct CertificateKeyMaterial<'a, 'b, A, PK> {
    pub(crate) tbs_key_material: SpkiKeyMaterial<'a, A>,
    pub(crate) signing_key: &'b mut PK,
}

impl<'a, A: Clone> TbsKeys for SpkiKeyMaterial<'a, A> {
    type Spki = DerSequence<'a>;
    type SigAlgorithm = A;

    fn spki(&mut self) -> Result<Self::Spki> {
        Ok(DerSequence::from(self.spki))
    }

    fn signature_algorithm(&self) -> Self::SigAlgorithm {
        self.signature_algorithm.clone()
    }
}

impl<'a, PK: PkProvider, A: Clone> TbsKeys for SelfSigningKeyMaterial<'a, PK, A> {
    type Spki = DerSequence<'a>;
    type SigAlgorithm = A;

    fn spki(&mut self) -> Result<Self::Spki> {
        Ok(DerSequence::from(self.signing_key.write_public_key_der()?))
    }

    fn signature_algorithm(&self) -> Self::SigAlgorithm {
        self.signature_algorithm.clone()
    }
}

impl<PK: PkProvider, A: Clone> CertificateKeys for SelfSigningKeyMaterial<'_, PK, A> {
    type Pk = PK;

    fn private_key(&mut self) -> &mut PK {
        self.signing_key
    }

    fn is_self_signed(&self) -> bool {
        true
    }
}

impl<'a, A: Clone, PK> TbsKeys for CertificateKeyMaterial<'a, '_, A, PK> {
    type Spki = DerSequence<'a>;
    type SigAlgorithm = A;

    fn spki(&mut self) -> Result<Self::Spki> {
        self.tbs_key_material.spki()
    }

    fn signature_algorithm(&self) -> Self::SigAlgorithm {
        self.tbs_key_material.signature_algorithm()
    }
}

impl<A: Clone, PK> CertificateKeys for CertificateKeyMaterial<'_, '_, A, PK> {
    type Pk = PK;

    fn private_key(&mut self) -> &mut PK {
        self.signing_key
    }
}
