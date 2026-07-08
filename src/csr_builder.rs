use std::borrow::BorrowMut;
use std::ops::{Deref, DerefMut};

use pkix::bit_vec::BitVec;
use pkix::pkcs10::{CertificationRequest, CertificationRequestInfo};
use pkix::types::{Attribute, DerSequence};
use pkix::{oid, DerWrite};

use crate::builder_common::Builder;
use crate::crypto_provider::{CryptoProvider, DefaultPkParameters, PkProvider, SigningAdapter};
use crate::error::{Error, Result, ValidationErrorType};
use crate::key_material::{CertificateKeys, DefaultSelfSigningKeyMaterial, NoKeyMaterial, SelfSigningKeyMaterial, TbsKeys};
use crate::name_builder::Subject;
use crate::util::{attributes_contain_key, build_attributes, build_extensions};

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Csr(Vec<u8>);

impl Deref for Csr {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Csr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Csr> for Vec<u8> {
    fn from(value: Csr) -> Self {
        value.into_vec()
    }
}

impl Csr {
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn builder<'a>() -> Builder<CsrState<'a>> {
        Builder::<CsrState>::new()
    }
}

/// CSR-related state
pub struct CsrState<'a> {
    /// List of attributes that we will request from the CA.
    ///
    /// Caveat: do not include the [pkix::pkcs10::ExtensionRequest] attribute in here: use the regular builder interface for extensions, which the builder will add to the set of attributes.
    attributes: Vec<Attribute<'a>>,
}

impl Default for Builder<CsrState<'_>> {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder<CsrState<'_>> {
    pub fn new() -> Self {
        Builder::new_for_use_case(CsrState { attributes: Vec::new() })
    }
}

impl<'a, CP: CryptoProvider, S> Builder<CsrState<'a>, CP, NoKeyMaterial, S> {
    pub fn with_self_signing_key<A: SigningAdapter<CP::Pk>, K: BorrowMut<CP::Pk>>(
        self,
        signing_key: &mut K,
        signature_algorithm: A,
    ) -> Result<Builder<CsrState<'a>, CP, SelfSigningKeyMaterial<'_, CP::Pk, A>, S>> {
        let signing_key = signing_key.borrow_mut();
        A::allows_pk(signing_key)?;
        Ok(self.with_key_material(SelfSigningKeyMaterial {
            signing_key,
            signature_algorithm,
        }))
    }

    pub fn with_generated_self_signing_key<A>(
        self,
        signature_algorithm: A,
    ) -> Builder<CsrState<'a>, CP, DefaultSelfSigningKeyMaterial<A>, S> {
        self.with_key_material(DefaultSelfSigningKeyMaterial(signature_algorithm))
    }
}

impl<'a, CP, K, S> Builder<CsrState<'a>, CP, K, S> {
    pub fn with_attributes<It>(mut self, attributes: It) -> Result<Self>
    where
        It: IntoIterator<Item = Attribute<'a>>,
    {
        // Reset extensions first
        self.use_case_state.attributes = Vec::new();
        self.append_attributes(attributes)
    }

    pub fn append_attributes<It>(mut self, attributes: It) -> Result<Self>
    where
        It: IntoIterator<Item = Attribute<'a>>,
    {
        let mut attributes_vec = self.use_case_state.attributes;
        for cur_ex in attributes {
            // NOTE: since we currently always add the `BasicConstraints` header, the user-provided
            // attributes should not contain an additional `ExtensionRequest` attribute
            if attributes_contain_key(&attributes_vec, &cur_ex.oid) || cur_ex.oid == *oid::extensionRequest {
                return Err(Error::Validation(ValidationErrorType::DuplicateAttribute(cur_ex.oid)));
            }

            attributes_vec.push(cur_ex)
        }

        self.use_case_state.attributes = attributes_vec;
        Ok(self)
    }
}

impl<CP: CryptoProvider, A> Builder<CsrState<'_>, CP, SelfSigningKeyMaterial<'_, CP::Pk, A>, Subject>
where
    A: Clone + DerWrite + SigningAdapter<CP::Pk>,
{
    pub fn build_csr(mut self) -> Result<Csr> {
        let extensions = build_extensions(self.extensions, self.ca, self.subject_alternative_dns_names)?;
        let csr_info = CertificationRequestInfo {
            subject: self.subject.0,
            spki: self.key_material.spki()?,
            attributes: build_attributes(self.use_case_state.attributes, extensions)?,
        };

        let reqinfo = pkix::yasna::construct_der(|writer| csr_info.write(writer));

        let sig = self.key_material.private_key().sign_data::<A>(&reqinfo)?;

        Ok(Csr(pkix::yasna::construct_der(|writer| {
            CertificationRequest {
                reqinfo: DerSequence::from(reqinfo),
                sigalg: self.key_material.signature_algorithm(),
                sig: BitVec::from_bytes(&sig),
            }
            .write(writer)
        })))
    }
}

impl<A, CP: CryptoProvider> Builder<CsrState<'_>, CP, DefaultSelfSigningKeyMaterial<A>, Subject>
where
    A: Clone + DefaultPkParameters<CP::Pk> + DerWrite + SigningAdapter<CP::Pk>,
{
    pub fn build_csr_generate_key(mut self) -> Result<(Csr, CP::Pk)> {
        let mut signing_key = <A as DefaultPkParameters<_>>::generate_pk(self.crypto_provider.rng())?;

        let new_builder = self.with_key_material_fun(|key_material| SelfSigningKeyMaterial {
            signing_key: &mut signing_key,
            signature_algorithm: key_material.0,
        });
        Ok((new_builder.build_csr()?, signing_key))
    }
}
