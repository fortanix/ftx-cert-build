use mbedtls::hash::{self, Type as HashType};
use mbedtls::pk::{Pk, Type as PkType, ECDSA_MAX_LEN};
use mbedtls::rng::{Random, Rdrand};
#[cfg(feature = "rsa")]
use pkix::types::RsaPkcs15;
use pkix::types::Sha256;
#[cfg(feature = "ecdsaecdh")]
use {mbedtls::pk::EcGroupId, pkix::types::EcdsaX962};

use crate::cert_builder::CertificateState;
#[cfg(feature = "ecdsaecdh")]
use crate::crypto_provider::{CryptoProvider, DefaultPkParameters};
use crate::crypto_provider::{PkProvider, SigningAdapter};
use crate::csr_builder::CsrState;
use crate::error::Result;
use crate::{Builder, Certificate, Csr};

impl PkProvider for Pk {
    type SignatureAlgorithm = PkType;

    type SignatureMeta = MbedtlsSignatureMeta;

    type HashAlgorithm = HashType;

    type HashMeta = MbedtlsHashMeta;

    fn sign_data<A: SigningAdapter<Self>>(&mut self, data: &[u8]) -> Result<Vec<u8>>
    where
        Self: Sized,
    {
        let mut digest = vec![0u8; A::hash_meta().hash_len];
        hash::Md::hash(A::hash_algorithm(), data, &mut digest)?;

        let mut sig = vec![0; A::signature_meta(self)?.signature_max_len];
        let len = self.sign(A::hash_algorithm(), &digest, sig.as_mut_slice(), &mut Rdrand)?;
        sig.truncate(len);
        Ok(sig)
    }

    fn write_public_key_der(&mut self) -> Result<Vec<u8>> {
        Ok(self.write_public_der_vec()?)
    }

    fn signature_algorithm(&self) -> Self::SignatureAlgorithm {
        self.pk_type()
    }
}

/// Trait that ensures that a pkix hash algorithm is compatible with the [mbedtls] crate.
trait PkixMbedTlsHashAdapter {
    fn mbedtls_hash_algorithm() -> HashType;

    fn mbedtls_hash_meta() -> MbedtlsHashMeta;
}

pub struct MbedtlsSignatureMeta {
    /// Maximum required length of the signature for a given PK and signature algorithm. Required because
    /// the mbedtls API requires allocating a buffer with at least this size.
    signature_max_len: usize,
}

pub struct MbedtlsHashMeta {
    /// Length of the hash for a hash algorithm. Required because the mbedtls API requires
    /// allocating a buffer with at least this size.
    hash_len: usize,
}

#[cfg(feature = "ecdsaecdh")]
impl<H: PkixMbedTlsHashAdapter> SigningAdapter<Pk> for EcdsaX962<H> {
    fn signature_algorithm() -> <Pk as PkProvider>::SignatureAlgorithm {
        PkType::Ecdsa
    }

    fn signature_meta(_pk: &Pk) -> Result<<Pk as PkProvider>::SignatureMeta> {
        Ok(MbedtlsSignatureMeta {
            signature_max_len: ECDSA_MAX_LEN,
        })
    }

    fn hash_algorithm() -> HashType {
        H::mbedtls_hash_algorithm()
    }

    fn hash_meta() -> <Pk as PkProvider>::HashMeta {
        H::mbedtls_hash_meta()
    }
}

#[cfg(feature = "rsa")]
impl<H: PkixMbedTlsHashAdapter> SigningAdapter<Pk> for RsaPkcs15<H> {
    fn signature_algorithm() -> <Pk as PkProvider>::SignatureAlgorithm {
        PkType::Rsa
    }

    fn signature_meta(pk: &Pk) -> Result<<Pk as PkProvider>::SignatureMeta> {
        Ok(MbedtlsSignatureMeta {
            signature_max_len: pk.len().div_ceil(8),
        })
    }

    fn hash_algorithm() -> HashType {
        H::mbedtls_hash_algorithm()
    }

    fn hash_meta() -> <Pk as PkProvider>::HashMeta {
        H::mbedtls_hash_meta()
    }
}

/// Currently, `pkix` only really supports [Sha256]
/// Additionally, we only support [Sha256] the Mbedtls API does not perform extra checks on
/// whether we pick a valid hash algorithm to go with the signature algorithm
impl PkixMbedTlsHashAdapter for Sha256 {
    fn mbedtls_hash_algorithm() -> HashType {
        HashType::Sha256
    }

    fn mbedtls_hash_meta() -> MbedtlsHashMeta {
        const SHA256_BYTE_LEN: usize = 32;
        MbedtlsHashMeta {
            hash_len: SHA256_BYTE_LEN,
        }
    }
}

/// For ECDSA, the default is [PkAlgorithm::EcdsaEcdh] with [EcGroupId::SecP256R1]
#[cfg(feature = "ecdsaecdh")]
impl<H> DefaultPkParameters<Pk> for EcdsaX962<H> {
    fn generate_pk<R: Random>(rng: &mut R) -> Result<Pk> {
        Ok(Pk::generate_ec(rng, EcGroupId::SecP256R1)?)
    }
}

pub struct MbedtlsCryptoProvider {
    rng: Rdrand,
}

impl MbedtlsCryptoProvider {
    fn new() -> Self {
        Self { rng: Rdrand }
    }
}

impl CryptoProvider for MbedtlsCryptoProvider {
    type Pk = Pk;

    type Rng = Rdrand;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }
}

impl Certificate {
    /// Build (tbs)certificates using PKI types and RNG from `FtxCrypto`
    pub fn mbedtls_crypto_builder() -> Builder<CertificateState, MbedtlsCryptoProvider> {
        Self::builder().with_crypto_provider(MbedtlsCryptoProvider::new())
    }
}

impl Csr {
    /// Build CSRs using PKI types and RNG from `FtxCrypto`
    pub fn mbedtls_crypto_builder<'a>() -> Builder<CsrState<'a>, MbedtlsCryptoProvider> {
        Self::builder().with_crypto_provider(MbedtlsCryptoProvider::new())
    }
}
