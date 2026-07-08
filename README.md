# Fortanix certificate building utilities

## Crate contents

This crate provides utilities for building the following:

1. Certificate Signing Requests (CSRs) as specified by PKC#10
2. To Be Signed certificates (TBS) as specified by X.509
3. Regular public key certificates as specified by X.509
4. Subject and Issuer structures to be consumed by the structures
  described int he previous three bullet points

Each of these is implemented through a different instantiation of the builder pattern, where
code for 1., 2., and 3. overlaps to a relatively large extent.

## Usage

The entry point for each of the above items is as follows:

1. [`Csr`](./src/csr_builder.rs) has a `builder` method to start constructing a CSR. At the end, one calls `build_csr` or `build_cert_generate_key` after respectively passing in their own key material, or requesting that key material be generated using default parameters.
2. [`TbsCertificate`](./src/cert_builder.rs) has a `builder` method to start constructing a TBS certificate. At the end, one calls `build_tbs` to generate the result.
3. [`Certificate`](./src/cert_builder.rs) has a `builder` method to start constructing a certificate. At the end, one calls `build_cert` or one of two `build_cert_generate_key` methods, depending on whether keys are supplied by the user or generated with default parameters by the builder.
4. [`NameBuilder`](./src/name_builder.rs) has methods `build_subject` and `build_issuer` to build `Subject`s and `Issuer`s, respectively

## Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

# License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.
