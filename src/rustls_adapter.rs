/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::sync::Arc;

#[cfg(feature = "ecdsaecdh")]
use pkix::types::EcdsaX962;
#[cfg(feature = "rsa")]
use pkix::types::RsaPkcs15;
#[cfg(any(feature = "rsa", feature = "ecdsaecdh"))]
use pkix::types::Sha256;
use rustls::crypto::hash::HashAlgorithm;
use rustls::crypto::CryptoProvider;
use rustls::sign::SigningKey;
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls_pki_types::PrivateKeyDer;

use crate::cert_builder::CertificateState;
use crate::crypto_provider::CryptoProvider as CrateCryptoProvider;
#[cfg(any(feature = "rsa", feature = "ecdsaecdh"))]
use crate::crypto_provider::DefaultPkParameters;
use crate::crypto_provider::PkProvider;
use crate::crypto_provider::SigningAdapter;
use crate::csr_builder::CsrState;
use crate::error::{Error, Result};
use crate::{Builder, Certificate, Csr};

impl From<aws_lc_rs::error::Unspecified> for Error {
    fn from(err: aws_lc_rs::error::Unspecified) -> Self {
        Self::CryptoProvider(err.into())
    }
}

#[derive(Clone, Debug)]
pub struct RustlsPk {
    key: Arc<dyn SigningKey>,
}

impl RustlsPk {
    pub(crate) fn from_der(key: PrivateKeyDer<'static>, provider: &CryptoProvider) -> Result<Self> {
        let key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|err| Error::CryptoProvider(err.into()))?;
        Ok(Self { key })
    }
}

impl PkProvider for RustlsPk {
    type SignatureAlgorithm = SignatureAlgorithm;

    type SignatureMeta = ();

    type HashAlgorithm = HashAlgorithm;

    type HashMeta = ();

    fn sign_data<A: SigningAdapter<Self>>(&mut self, data: &[u8]) -> Result<Vec<u8>>
    where
        Self: Sized,
    {
        let scheme = match (A::signature_algorithm(), A::hash_algorithm()) {
            (SignatureAlgorithm::RSA, HashAlgorithm::SHA256) => SignatureScheme::RSA_PKCS1_SHA256,
            (SignatureAlgorithm::ECDSA, HashAlgorithm::SHA256) => SignatureScheme::ECDSA_NISTP256_SHA256,
            _ => {
                return Err(Error::CryptoProvider(
                    "unsupported signature algorithm/hash combination".into(),
                ))
            }
        };
        let signer = self
            .key
            .choose_scheme(&[scheme])
            .ok_or_else(|| Error::CryptoProvider("private key does not support the requested signature scheme".into()))?;
        // Rustls hashes the message internally according to the selected scheme.
        signer.sign(data).map_err(|err| Error::CryptoProvider(err.into()))
    }

    fn write_public_key_der(&mut self) -> Result<Vec<u8>> {
        let public_key = self
            .key
            .public_key()
            .ok_or_else(|| Error::CryptoProvider("rustls signing key does not expose a public key".into()))?;
        Ok(public_key.to_vec())
    }

    fn signature_algorithm(&self) -> Self::SignatureAlgorithm {
        self.key.algorithm()
    }
}

#[cfg(feature = "rsa")]
impl SigningAdapter<RustlsPk> for RsaPkcs15<Sha256> {
    fn signature_algorithm() -> <RustlsPk as PkProvider>::SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }

    fn signature_meta(_pk: &RustlsPk) -> Result<<RustlsPk as PkProvider>::SignatureMeta> {
        Ok(())
    }

    fn hash_algorithm() -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn hash_meta() -> <RustlsPk as PkProvider>::HashMeta {}
}

/// ECDSA with SHA-256 using a P-256 key.
#[cfg(feature = "ecdsaecdh")]
impl SigningAdapter<RustlsPk> for EcdsaX962<Sha256> {
    fn signature_algorithm() -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn signature_meta(_pk: &RustlsPk) -> Result<<RustlsPk as PkProvider>::SignatureMeta> {
        Ok(())
    }

    fn hash_algorithm() -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn hash_meta() -> <RustlsPk as PkProvider>::HashMeta {}
}

/// Generate an RSA-2048 key with public exponent 65537 using internal AWS-LC randomness.
#[cfg(feature = "rsa")]
impl<H> DefaultPkParameters<RustlsCryptoProvider> for RsaPkcs15<H> {
    fn generate_pk(crypto_provider: &mut RustlsCryptoProvider) -> Result<RustlsPk> {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        use aws_lc_rs::rsa::{KeyPair, KeySize};

        let key = KeyPair::generate(KeySize::Rsa2048)?;
        let der = AsDer::<Pkcs8V1Der>::as_der(&key)?;
        RustlsPk::from_der(PrivateKeyDer::Pkcs8(der.as_ref().to_vec().into()), &crypto_provider.provider)
    }
}

/// Generate a P-256 key using internal AWS-LC randomness.
#[cfg(feature = "ecdsaecdh")]
impl<H> DefaultPkParameters<RustlsCryptoProvider> for EcdsaX962<H> {
    fn generate_pk(crypto_provider: &mut RustlsCryptoProvider) -> Result<RustlsPk> {
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)?;
        let der = key.to_pkcs8v1()?;
        RustlsPk::from_der(PrivateKeyDer::Pkcs8(der.as_ref().to_vec().into()), &crypto_provider.provider)
    }
}

pub struct RustlsCryptoProvider {
    provider: CryptoProvider,
}

impl Default for RustlsCryptoProvider {
    fn default() -> Self {
        Self::with_provider(rustls::crypto::aws_lc_rs::default_provider())
    }
}

impl RustlsCryptoProvider {
    /// Use an explicit rustls provider when loading generated keys.
    pub fn with_provider(provider: CryptoProvider) -> Self {
        Self { provider }
    }

    /// Use the AWS-LC rustls provider without installing a global provider.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CrateCryptoProvider for RustlsCryptoProvider {
    type Pk = RustlsPk;

    fn fill_random(&mut self, bytes: &mut [u8]) -> Result<()> {
        getrandom::fill(bytes).map_err(|err| Error::CryptoProvider(err.into()))
    }
}

impl Certificate {
    /// Build (tbs)certificates using PKI types and system randomness.
    pub fn rustls_crypto_builder() -> Builder<CertificateState, RustlsCryptoProvider> {
        Self::builder().with_crypto_provider(RustlsCryptoProvider::new())
    }

    pub fn rustls_crypto_builder_with_provider(provider: CryptoProvider) -> Builder<CertificateState, RustlsCryptoProvider> {
        Self::builder().with_crypto_provider(RustlsCryptoProvider::with_provider(provider))
    }
}

impl Csr {
    /// Build CSRs using PKI types and system randomness.
    pub fn rustls_crypto_builder<'a>() -> Builder<CsrState<'a>, RustlsCryptoProvider> {
        Self::builder().with_crypto_provider(RustlsCryptoProvider::new())
    }

    pub fn rustls_crypto_builder_with_provider<'a>(provider: CryptoProvider) -> Builder<CsrState<'a>, RustlsCryptoProvider> {
        Self::builder().with_crypto_provider(RustlsCryptoProvider::with_provider(provider))
    }
}
