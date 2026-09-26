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
#[cfg(any(feature = "rsa", feature = "ecdsaecdh"))]
use rand_core::CryptoRng;
use rand_core::OsRng;
use rand_core::RngCore;
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
use crate::error::{Error, Result, ValidationErrorType};
use crate::{Builder, Certificate, Csr};

fn load_signing_key(key: &PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>> {
    let provider =
        CryptoProvider::get_default().ok_or_else(|| Error::Pki("no default rustls crypto provider installed".into()))?;
    provider
        .key_provider
        .load_private_key(key.clone_key())
        .map_err(|err| Error::Pki(err.to_string().into()))
}

impl PkProvider for PrivateKeyDer<'static> {
    type SignatureAlgorithm = SignatureAlgorithm;

    type SignatureMeta = RustlsSignatureMeta;

    type HashAlgorithm = HashAlgorithm;

    type HashMeta = RustlsHashMeta;

    fn sign_data<A: SigningAdapter<Self>>(&mut self, data: &[u8]) -> Result<Vec<u8>>
    where
        Self: Sized,
    {
        let key = load_signing_key(self)?;
        if key.algorithm() != A::signature_algorithm() {
            return Err(Error::Validation(ValidationErrorType::PkAndSigAlgMismatch));
        }
        let scheme = A::signature_meta(self)?.scheme;
        let signer = key
            .choose_scheme(&[scheme])
            .ok_or_else(|| Error::Pki("private key does not support the requested signature scheme".into()))?;
        // Rustls hashes the message internally according to the selected scheme.
        signer.sign(data).map_err(|err| Error::Pki(err.to_string().into()))
    }

    fn write_public_key_der(&mut self) -> Result<Vec<u8>> {
        let key = load_signing_key(self)?;
        let public_key = key
            .public_key()
            .ok_or_else(|| Error::Pki("rustls signing key does not expose a public key".into()))?;
        Ok(public_key.to_vec())
    }

    fn signature_algorithm(&self) -> Result<Self::SignatureAlgorithm> {
        Ok(load_signing_key(self)?.algorithm())
    }
}

pub struct RustlsSignatureMeta {
    pub scheme: SignatureScheme,
}

pub struct RustlsHashMeta {}

/// Maps a pkix hash to rustls hashing and compatible signature schemes.
#[cfg(any(feature = "rsa", feature = "ecdsaecdh"))]
trait PkixRustlsHashAdapter {
    fn rustls_hash_algorithm() -> HashAlgorithm;

    fn rustls_hash_meta() -> RustlsHashMeta;

    #[cfg(feature = "rsa")]
    const RSA_SCHEME: SignatureScheme;

    #[cfg(feature = "ecdsaecdh")]
    const ECDSA_SCHEME: SignatureScheme;
}

// As with the mbedtls adapter, only SHA-256 is currently supported.
#[cfg(any(feature = "rsa", feature = "ecdsaecdh"))]
impl PkixRustlsHashAdapter for Sha256 {
    fn rustls_hash_algorithm() -> HashAlgorithm {
        HashAlgorithm::SHA256
    }

    fn rustls_hash_meta() -> RustlsHashMeta {
        RustlsHashMeta {}
    }

    #[cfg(feature = "rsa")]
    const RSA_SCHEME: SignatureScheme = SignatureScheme::RSA_PKCS1_SHA256;

    #[cfg(feature = "ecdsaecdh")]
    const ECDSA_SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
}

#[cfg(feature = "rsa")]
impl<H: PkixRustlsHashAdapter> SigningAdapter<PrivateKeyDer<'static>> for RsaPkcs15<H> {
    fn signature_algorithm() -> <PrivateKeyDer<'static> as PkProvider>::SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }

    fn signature_meta(_pk: &PrivateKeyDer<'static>) -> Result<<PrivateKeyDer<'static> as PkProvider>::SignatureMeta> {
        Ok(RustlsSignatureMeta { scheme: H::RSA_SCHEME })
    }

    fn hash_algorithm() -> HashAlgorithm {
        H::rustls_hash_algorithm()
    }

    fn hash_meta() -> <PrivateKeyDer<'static> as PkProvider>::HashMeta {
        H::rustls_hash_meta()
    }
}

/// ECDSA using the curve and hash selected by the hash adapter.
#[cfg(feature = "ecdsaecdh")]
impl<H: PkixRustlsHashAdapter> SigningAdapter<PrivateKeyDer<'static>> for EcdsaX962<H> {
    fn signature_algorithm() -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn signature_meta(_pk: &PrivateKeyDer<'static>) -> Result<RustlsSignatureMeta> {
        Ok(RustlsSignatureMeta { scheme: H::ECDSA_SCHEME })
    }

    fn hash_algorithm() -> HashAlgorithm {
        H::rustls_hash_algorithm()
    }

    fn hash_meta() -> RustlsHashMeta {
        H::rustls_hash_meta()
    }
}

/// Generate an RSA-2048 key with public exponent 65537 (default) using the supplied RNG.
#[cfg(feature = "rsa")]
impl<H, R: RngCore + CryptoRng> DefaultPkParameters<PrivateKeyDer<'static>, R> for RsaPkcs15<H> {
    fn generate_pk(rng: &mut R) -> Result<PrivateKeyDer<'static>> {
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::new(rng, 2048).map_err(|err| Error::Pki(err.to_string().into()))?;
        let der = key.to_pkcs8_der().map_err(|err| Error::Pki(err.to_string().into()))?;
        Ok(PrivateKeyDer::Pkcs8(der.as_bytes().to_vec().into()))
    }
}

/// Generate a P-256 key using the supplied RNG.
#[cfg(feature = "ecdsaecdh")]
impl<H, R: RngCore + CryptoRng> DefaultPkParameters<PrivateKeyDer<'static>, R> for EcdsaX962<H> {
    fn generate_pk(rng: &mut R) -> Result<PrivateKeyDer<'static>> {
        use p256::pkcs8::EncodePrivateKey;
        let key = p256::SecretKey::random(rng);
        let der = key.to_pkcs8_der().map_err(|err| Error::Pki(err.to_string().into()))?;
        Ok(PrivateKeyDer::Pkcs8(der.as_bytes().to_vec().into()))
    }
}

#[derive(Default)]
pub struct RustlsCryptoProvider {
    rng: OsRng,
}

impl RustlsCryptoProvider {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CrateCryptoProvider for RustlsCryptoProvider {
    type Pk = PrivateKeyDer<'static>;
    type Rng = OsRng;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }

    fn fill_random(&mut self, bytes: &mut [u8]) -> Result<()> {
        self.rng
            .try_fill_bytes(bytes)
            .map_err(|err| Error::Pki(err.to_string().into()))
    }
}

impl Certificate {
    /// Build (tbs)certificates using PKI types and OsRng
    pub fn rustls_crypto_builder() -> Builder<CertificateState, RustlsCryptoProvider> {
        Self::builder().with_crypto_provider(RustlsCryptoProvider::new())
    }
}

impl Csr {
    /// Build CSRs using PKI types and OsRng
    pub fn rustls_crypto_builder<'a>() -> Builder<CsrState<'a>, RustlsCryptoProvider> {
        Self::builder().with_crypto_provider(RustlsCryptoProvider::new())
    }
}
