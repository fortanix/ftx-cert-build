/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::BorrowMut;
use std::ops::{Deref, DerefMut};

use chrono::{DateTime, Duration, Utc};
use mbedtls::rng::Random;
use pkix::bit_vec::BitVec;
use pkix::num_bigint::BigUint;
use pkix::types::{DateTime as PkixDateTime, DerSequence, SignatureAlgorithm};
use pkix::x509::{Certificate as PkixCertificate, TbsCertificate as PkixTbsCertificate, TBS_CERTIFICATE_V3};
use pkix::yasna::construct_der;
use pkix::DerWrite;

use crate::builder_common::Builder;
use crate::crypto_provider::{CryptoProvider, DefaultPkParameters, PkProvider, SigningAdapter};
use crate::error::{Error, Result, ValidationErrorType};
use crate::key_material::{
    CertificateKeyMaterial, CertificateKeys, DefaultSelfSigningKeyMaterial, NoKeyMaterial, SelfSigningKeyMaterial,
    SpkiKeyMaterial, TbsKeys,
};
use crate::name_builder::{Issuer, Subject};
use crate::util::build_extensions;

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Certificate(Vec<u8>);

impl Deref for Certificate {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Certificate {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Certificate> for Vec<u8> {
    fn from(value: Certificate) -> Self {
        value.into_vec()
    }
}

impl Certificate {
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn builder() -> Builder<CertificateState> {
        Builder::<CertificateState>::new()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TbsCertificate(Vec<u8>);

impl Deref for TbsCertificate {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TbsCertificate {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<TbsCertificate> for Vec<u8> {
    fn from(value: TbsCertificate) -> Self {
        value.into_vec()
    }
}

impl TbsCertificate {
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// Certificate-related state, used for tbs and certificates
pub struct CertificateState<I = NoIssuer, L = NoCertLifetime> {
    /// Name of the issuer of the certificate.
    issuer: I,

    /// When the certificate becomes active.
    ///
    /// The default is right now.
    validity_notbefore: Option<DateTime<Utc>>,

    /// When the certificate expires.
    validity_lifetime: L,
}

#[derive(Clone, Debug)]
pub struct NoCertLifetime;
#[derive(Clone, Debug)]
pub enum CertLifetime {
    Duration(Duration),
    NotAfter(DateTime<Utc>),
}

#[derive(Clone, Debug)]
pub struct NoIssuer;

struct ValidatedCertificateState {
    issuer: Issuer,
    validity_notbefore: PkixDateTime,
    validity_notafter: PkixDateTime,
}

impl CertificateState<Issuer, CertLifetime> {
    fn build_state(self) -> Result<ValidatedCertificateState> {
        // inject default value
        let validity_notbefore = self.validity_notbefore.unwrap_or_else(Utc::now);

        let validity_notafter = match self.validity_lifetime {
            CertLifetime::Duration(duration) => validity_notbefore
                .checked_add_signed(duration)
                .ok_or(Error::Validation(ValidationErrorType::DurationOverflow))?,
            CertLifetime::NotAfter(date_time) => date_time,
        };

        if validity_notbefore > validity_notafter {
            return Err(Error::Validation(ValidationErrorType::NotBeforeAfterNotAfter));
        }

        Ok(ValidatedCertificateState {
            issuer: self.issuer,
            validity_notafter: validity_notafter.into(),
            validity_notbefore: validity_notbefore.into(),
        })
    }
}

impl Default for Builder<CertificateState> {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder<CertificateState> {
    pub fn new() -> Self {
        Builder::new_for_use_case(CertificateState {
            issuer: NoIssuer,
            validity_notbefore: None,
            validity_lifetime: NoCertLifetime,
        })
    }
}

impl<I, L, CP, K, S> Builder<CertificateState<I, L>, CP, K, S> {
    pub fn with_validity_notbefore(mut self, validity_notbefore: DateTime<Utc>) -> Builder<CertificateState<I, L>, CP, K, S> {
        self.use_case_state.validity_notbefore = Some(validity_notbefore);
        self
    }
}

impl<I, CP, K, S> Builder<CertificateState<I, NoCertLifetime>, CP, K, S> {
    pub fn with_validity_duration(self, validity_duration: Duration) -> Builder<CertificateState<I, CertLifetime>, CP, K, S> {
        self.with_cert_lifetime(CertLifetime::Duration(validity_duration))
    }

    /// Warning: if you use this method with a `validity_notafter` that is relative to the current time, you likely do not want to use the default `now` value for `validity_notbefore` since these two values of now might be different.
    pub fn with_validity_notafter(
        self,
        validity_notafter: DateTime<Utc>,
    ) -> Builder<CertificateState<I, CertLifetime>, CP, K, S> {
        self.with_cert_lifetime(CertLifetime::NotAfter(validity_notafter))
    }

    fn with_cert_lifetime(self, cert_lifetime: CertLifetime) -> Builder<CertificateState<I, CertLifetime>, CP, K, S> {
        let Builder {
            crypto_provider,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state: cert,
        } = self;

        Builder {
            crypto_provider,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state: CertificateState {
                issuer: cert.issuer,
                validity_notbefore: cert.validity_notbefore,
                validity_lifetime: cert_lifetime,
            },
        }
    }
}

impl<L, CP, K, S> Builder<CertificateState<NoIssuer, L>, CP, K, S> {
    pub fn with_issuer(self, issuer: Issuer) -> Builder<CertificateState<Issuer, L>, CP, K, S> {
        let Builder {
            crypto_provider,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state: cert,
        } = self;

        Builder {
            crypto_provider,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state: CertificateState {
                issuer,
                validity_notbefore: cert.validity_notbefore,
                validity_lifetime: cert.validity_lifetime,
            },
        }
    }
}

impl<L, CP, K> Builder<CertificateState<NoIssuer, L>, CP, K, Subject> {
    pub fn with_subject_as_issuer(self) -> Builder<CertificateState<Issuer, L>, CP, K, Subject> {
        let issuer = self.subject.clone().into();
        self.with_issuer(issuer)
    }
}

/// This impl's generics exclude using it on [Csr]'s, since they are always self-signed and should hence be
/// instantiated as such.
impl<I, CP, L, S> Builder<CertificateState<I, L>, CP, NoKeyMaterial, S> {
    pub fn with_spki<A>(
        self,
        spki: &[u8],
        signature_algorithm: A,
    ) -> Builder<CertificateState<I, L>, CP, SpkiKeyMaterial<'_, A>, S> {
        self.with_key_material(SpkiKeyMaterial {
            spki,
            signature_algorithm,
        })
    }
}

impl<L, CP: CryptoProvider> Builder<CertificateState<NoIssuer, L>, CP, NoKeyMaterial, Subject> {
    pub fn with_self_signing_key<A: SigningAdapter<CP::Pk>, K: BorrowMut<CP::Pk>>(
        self,
        signing_key: &mut K,
        signature_algorithm: A,
    ) -> Result<Builder<CertificateState<Issuer, L>, CP, SelfSigningKeyMaterial<'_, CP::Pk, A>, Subject>> {
        let signing_key = signing_key.borrow_mut();
        A::allows_pk(signing_key)?;
        Ok(self.with_subject_as_issuer().with_key_material(SelfSigningKeyMaterial {
            signing_key,
            signature_algorithm,
        }))
    }

    pub fn with_generated_self_signing_key<A>(
        self,
        signature_algorithm: A,
    ) -> Builder<CertificateState<Issuer, L>, CP, DefaultSelfSigningKeyMaterial<A>, Subject> {
        self.with_subject_as_issuer()
            .with_key_material(DefaultSelfSigningKeyMaterial(signature_algorithm))
    }
}

impl<'a, I, L, CP: CryptoProvider, A, S> Builder<CertificateState<I, L>, CP, SpkiKeyMaterial<'a, A>, S> {
    pub fn with_signing_key<'b, K: BorrowMut<CP::Pk>>(
        self,
        signing_key: &'b mut K,
    ) -> Result<Builder<CertificateState<I, L>, CP, CertificateKeyMaterial<'a, 'b, A, CP::Pk>, S>>
    where
        A: SigningAdapter<CP::Pk>,
    {
        let signing_key = signing_key.borrow_mut();
        A::allows_pk(signing_key)?;
        Ok(self.with_key_material_fun(|old_key_material| CertificateKeyMaterial {
            tbs_key_material: old_key_material,
            signing_key,
        }))
    }
}

impl<CP: CryptoProvider, K: TbsKeys> Builder<CertificateState<Issuer, CertLifetime>, CP, K, Subject>
where
    <K as TbsKeys>::SigAlgorithm: DerWrite + SignatureAlgorithm,
    <K as TbsKeys>::Spki: DerWrite,
{
    pub fn build_tbs(self) -> Result<TbsCertificate> {
        let tbscert = self.build_tbs_struct()?;
        Ok(TbsCertificate(construct_der(|writer| tbscert.write(writer))))
    }

    fn build_tbs_struct(mut self) -> Result<PkixTbsCertificate<BigUint, <K as TbsKeys>::SigAlgorithm, <K as TbsKeys>::Spki>> {
        const SERIAL_BYTE_LENGTH: usize = 20;
        let mut serial = [0u8; SERIAL_BYTE_LENGTH];
        self.crypto_provider.rng().random(&mut serial)?;
        // Per RFC 5280, serial numbers must be positive, and at most 20 octets.
        // DER encoding of numbers with the MSB set would require an extra byte.
        serial[0] &= 0x7f;

        let extensions = build_extensions(self.extensions, self.ca, self.subject_alternative_dns_names)?;

        let ValidatedCertificateState {
            issuer: issuer_name,
            validity_notbefore,
            validity_notafter,
        } = self.use_case_state.build_state()?;

        Ok(PkixTbsCertificate {
            version: TBS_CERTIFICATE_V3,
            serial: BigUint::from_bytes_be(&serial),
            sigalg: self.key_material.signature_algorithm(),
            issuer: issuer_name.0,
            validity_notbefore,
            validity_notafter,
            subject: self.subject.0,
            spki: self.key_material.spki()?,
            extensions: extensions.0,
        })
    }
}

impl<CP: CryptoProvider, K: CertificateKeys<Pk = CP::Pk>> Builder<CertificateState<Issuer, CertLifetime>, CP, K, Subject>
where
    <K as TbsKeys>::SigAlgorithm: DerWrite + SigningAdapter<CP::Pk>,
    <K as TbsKeys>::Spki: DerWrite,
{
    pub fn build_cert(self) -> Result<Certificate> {
        // Pass in a borrow so that our private key does not get consumed when we build the tbs
        let (no_key_builder, mut key_material) = self.swap_key_material(NoKeyMaterial);
        let tbs_builder = no_key_builder.with_key_material(&mut key_material);
        let tbscert = tbs_builder.build_tbs()?;

        let sig = key_material
            .private_key()
            .sign_data::<<K as TbsKeys>::SigAlgorithm>(&tbscert)?;

        let cert = construct_der(|writer| {
            PkixCertificate {
                tbscert: DerSequence::from(tbscert.into_vec()),
                sigalg: key_material.signature_algorithm(),
                sig: BitVec::from_bytes(&sig),
            }
            .write(writer);
        });
        Ok(Certificate(cert))
    }
}

impl<CP: CryptoProvider, A> Builder<CertificateState<Issuer, CertLifetime>, CP, DefaultSelfSigningKeyMaterial<A>, Subject>
where
    A: Clone + DefaultPkParameters<CP::Pk> + DerWrite + SigningAdapter<CP::Pk>,
{
    pub fn build_cert_generate_key(mut self) -> Result<(Certificate, CP::Pk)> {
        let mut signing_key = <A as DefaultPkParameters<_>>::generate_pk(self.crypto_provider.rng())?;

        let new_builder = self.with_key_material_fun(|key_material| SelfSigningKeyMaterial {
            signing_key: &mut signing_key,
            signature_algorithm: key_material.0,
        });
        Ok((new_builder.build_cert()?, signing_key))
    }
}

impl<CP: CryptoProvider, A> Builder<CertificateState<Issuer, CertLifetime>, CP, SpkiKeyMaterial<'_, A>, Subject>
where
    A: Clone + DefaultPkParameters<CP::Pk> + DerWrite + SigningAdapter<CP::Pk>,
{
    pub fn build_cert_generate_key(mut self) -> Result<(Certificate, CP::Pk)> {
        let mut signing_key = <A as DefaultPkParameters<_>>::generate_pk(self.crypto_provider.rng())?;

        let new_builder = self.with_signing_key(&mut signing_key)?;
        Ok((new_builder.build_cert()?, signing_key))
    }
}
