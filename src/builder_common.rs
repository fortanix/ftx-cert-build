/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkix::oid;
use pkix::types::{Extension, Extensions, GeneralName};

use crate::crypto_provider::{CryptoProvider, NoCryptoProvider};
use crate::error::{Error, Result, ValidationErrorType};
use crate::key_material::NoKeyMaterial;
use crate::name_builder::Subject;
use crate::util::{extensions_contain_key, san_extension_from_general_names};

/// Builder that provides a simple interface for creating:
/// 1. TBS certificates (v3)
/// 2. X509 Certificates (v3, self-signed and non self-signed)
/// 3. CSRs
#[derive(Clone, Debug)]
#[must_use]
pub struct Builder<C, CP = NoCryptoProvider, K = NoKeyMaterial, S = NoSubject> {
    /// Type of CP accepted by this builder (e.g. mbedtls)
    pub(crate) crypto_provider: CP,

    /// Name of the subject of the certificate.
    pub(crate) subject: S,

    /// Extensions to be set on the certificate.
    ///
    /// Caveats:
    /// * the [pkix::x509::SubjectAltName] extensions should either be set
    ///   here or as separate options, but not in both places.
    /// * the [pkix::x509::BasicConstraints] extension should not be set; we generate our own
    ///   based on the value of [Self::ca]
    pub(crate) extensions: Extensions,

    /// A list of Subject Alternate Name values. If specified, the [Self::extensions] field must
    /// not contain its own Subject Alternative Name extension value.
    pub(crate) subject_alternative_dns_names: Option<Extension>,

    /// Whether the certificate should be usable as a CA certificate; influences the
    /// generation of the [pkix::x509::BasicConstraints] extension.
    ///
    /// The default is `false`.
    pub(crate) ca: bool,

    /// The key material required to generate a tbs certificate or proper certificate.
    ///
    /// This is just a public key in case of a tbs or csr, and both a public and private key
    /// otherwise.
    pub(crate) key_material: K,

    /// Use-case specific state.
    pub(crate) use_case_state: C,
}

#[derive(Clone, Debug)]
pub struct NoSubject;

impl<C> Builder<C> {
    pub(crate) fn new_for_use_case(use_case_state: C) -> Self {
        Builder {
            crypto_provider: NoCryptoProvider,
            subject: NoSubject,
            extensions: Extensions(Vec::new()),
            subject_alternative_dns_names: None,
            ca: false,
            key_material: NoKeyMaterial,
            use_case_state,
        }
    }
}

impl<C, CP, K> Builder<C, CP, K, NoSubject> {
    pub fn with_subject(self, subject: Subject) -> Builder<C, CP, K, Subject> {
        let Builder {
            crypto_provider,
            subject: _,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state,
        } = self;

        Builder {
            crypto_provider,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state,
        }
    }
}

impl<C, K, S> Builder<C, NoCryptoProvider, K, S> {
    pub fn with_crypto_provider<CP: CryptoProvider>(self, crypto_provider: CP) -> Builder<C, CP, K, S> {
        let Builder {
            crypto_provider: _,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state,
        } = self;

        Builder {
            crypto_provider,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material,
            use_case_state,
        }
    }
}

/// Generic builder methods with no type-level effects
impl<C, CP, K, S> Builder<C, CP, K, S> {
    pub fn make_ca_certificate(mut self) -> Self {
        self.ca = true;
        self
    }

    pub fn with_extensions<It>(mut self, extensions: It) -> Result<Self>
    where
        It: IntoIterator<Item = Extension>,
    {
        // Reset extensions first
        self.extensions = Extensions(Vec::new());
        self.append_extensions(extensions)
    }

    pub fn append_extensions<It>(mut self, extensions: It) -> Result<Self>
    where
        It: IntoIterator<Item = Extension>,
    {
        let mut extensions_vec: Extensions = self.extensions;
        for cur_ex in extensions {
            if extensions_contain_key(&extensions_vec, &cur_ex.oid) || cur_ex.oid == *oid::basicConstraints {
                return Err(Error::Validation(ValidationErrorType::DuplicateExtension(cur_ex.oid)));
            }
            extensions_vec.push(cur_ex)
        }

        self.extensions = extensions_vec;
        Ok(self)
    }

    pub fn with_san_extension_from_general_names<'a>(mut self, sans: impl IntoIterator<Item = GeneralName<'a>>) -> Self {
        let san_extension = san_extension_from_general_names(sans);
        self.subject_alternative_dns_names = Some(san_extension);
        self
    }

    pub fn with_san_extension_from_strs<'a, It, N>(self, sans: It) -> Self
    where
        It: IntoIterator<Item = &'a N>,
        N: AsRef<str> + 'a,
    {
        self.with_san_extension_from_general_names(
            sans.into_iter()
                .map(|dns_name| GeneralName::DnsName(dns_name.as_ref().into())),
        )
    }
}

/// Internal, generic methods that we need to change key material state at some point
impl<C, CP, K, S> Builder<C, CP, K, S> {
    pub(crate) fn with_key_material<K2>(self, new_key_material: K2) -> Builder<C, CP, K2, S> {
        self.swap_key_material(new_key_material).0
    }

    pub(crate) fn with_key_material_fun<K2, UpdateFun>(self, new_key_material_fun: UpdateFun) -> Builder<C, CP, K2, S>
    where
        UpdateFun: FnOnce(K) -> K2,
    {
        let (builder_without_key_material, old_key_material) = self.swap_key_material(NoKeyMaterial);
        let (builder_with_new_material, NoKeyMaterial) =
            builder_without_key_material.swap_key_material(new_key_material_fun(old_key_material));
        builder_with_new_material
    }

    pub(crate) fn swap_key_material<K2>(self, new_key_material: K2) -> (Builder<C, CP, K2, S>, K) {
        let Builder {
            crypto_provider: _private_key,
            subject,
            extensions,
            subject_alternative_dns_names,
            ca,
            key_material: old_key_material,
            use_case_state,
        } = self;

        (
            Builder {
                crypto_provider: _private_key,
                subject,
                extensions,
                subject_alternative_dns_names,
                ca,
                key_material: new_key_material,
                use_case_state,
            },
            old_key_material,
        )
    }
}
