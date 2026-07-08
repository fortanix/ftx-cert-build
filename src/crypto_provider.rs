/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! File containing different traits and definitions that need to be instantiated by a specific crypto provider in order too use this library

use mbedtls::rng::Random;
use pkix::types::SignatureAlgorithm as PkixSignatureAlgorithm;

use crate::error::{Error, Result, ValidationErrorType};

pub trait CryptoProvider {
    type Pk: PkProvider;
    type Rng: Random;

    fn rng(&mut self) -> &mut Self::Rng;
}

#[derive(Clone, Debug)]
pub struct NoCryptoProvider;

/// Key pairs to be used as part of cert builders.
///
/// Parametrizing the crate by this trait allows us to plug in different crypto implementations
/// (mbedtls or other).
pub trait PkProvider {
    /// Type of signature algorithms supported by this Pk
    type SignatureAlgorithm: PartialEq;

    /// Metadata associated with signature algorithms under this PKI (e.g. a signature length)
    type SignatureMeta;

    /// Type of hash algorithms supported by this Pk
    type HashAlgorithm;

    /// Metadata associated with hash algorithms under this PKI (e.g. a hash length)
    type HashMeta;

    fn sign_data<A: SigningAdapter<Self>>(&mut self, data: &[u8]) -> Result<Vec<u8>>
    where
        Self: Sized;

    fn write_public_key_der(&mut self) -> Result<Vec<u8>>;

    fn signature_algorithm(&self) -> Self::SignatureAlgorithm;
}

/// Adapter trait to link a pkix signature algorithm to a `PkProvider`
/// and its supported hashing algorithms.
pub trait SigningAdapter<PK: PkProvider>: PkixSignatureAlgorithm {
    fn signature_algorithm() -> <PK as PkProvider>::SignatureAlgorithm;

    /// This function can error if the given `PK` does not have [Self::signature_algorithm] as its algorithm
    fn signature_meta(pk: &PK) -> Result<<PK as PkProvider>::SignatureMeta>;

    fn hash_algorithm() -> <PK as PkProvider>::HashAlgorithm;

    fn hash_meta() -> <PK as PkProvider>::HashMeta;

    fn allows_pk(pk: &PK) -> Result<()> {
        (pk.signature_algorithm() == Self::signature_algorithm())
            .then_some(())
            .ok_or(Error::Validation(ValidationErrorType::PkAndSigAlgMismatch))
    }
}

/// [pkix::types::SignatureAlgorithm]s that have default key parameters and can use those to
/// generate keys of type `PK`
pub trait DefaultPkParameters<PK> {
    fn generate_pk<R: Random>(rng: &mut R) -> Result<PK>;
}
