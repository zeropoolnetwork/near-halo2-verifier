Halo2 (Plonk) Verifier using NEAR Precompiles
=============================================

This crate implements a Verifier compatible with
[snark-verifier](https://github.com/zeropoolnetwork/snark-verifier/).  It
does most verification tasks natively in Rust, just like a traditional
[halo2](https://github.com/privacy-scaling-explorations/halo2) verifier would
with the only difference of calling [NEAR precompiled contracts](https://docs.rs/near-sys/latest/near_sys/fn.alt_bn128_pairing_check.html)
to perform group and pairing operations in Bn256.

This crate is used by [ZeroPool](https://github.com/zeropoolnetwork/zeropool-near/) smart-contract for NEAR.
But it's generic enough to verify any Halo2 circuit.
