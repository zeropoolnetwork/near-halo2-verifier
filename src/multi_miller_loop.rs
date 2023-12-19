pub use halo2_curves::pairing::{
    MultiMillerLoop,
    Engine,
};
use halo2_curves::{
    bn256::{
        Bn256,
        G2Affine,
        Gt,
    },
};

/// We define this to override [MultiMillerLoop] implementation of [Bn256].
///
/// We could have used Bn256 directly, but we keep our own type
/// with `unreachable!()` in implementations for documentation
/// purposes. This explicitly shows that the [Engine::pairing] and
/// [MultiMillerLoop::multi_miller_loop] are never called.
///
/// These traits are, in fact, reduntant and [snark_verifier] shouldn't require
/// us to implement them. The only thing it actually needs is the relationship
/// between groups defined in [Engine].
#[derive(Clone, Debug)]
pub struct NearBn256;

/// We implement [Engine] only because [MultiMillerLoop] depends on it.
impl Engine for NearBn256 {
    type Scalar = <Bn256 as Engine>::Scalar;

    type G1 = <Bn256 as Engine>::G1;
    type G1Affine = <Bn256 as Engine>::G1Affine;
    type G2 = <Bn256 as Engine>::G2;
    type G2Affine = <Bn256 as Engine>::G2Affine;
    type Gt = <Bn256 as Engine>::Gt;

    fn pairing(_p: &Self::G1Affine, _q: &Self::G2Affine) -> Self::Gt {
        // We leave it unimplemented since NEAR doesn't have a precompiled
        // contract for it. It seems that `impl Engine` is reduntand here, and
        // we have to implement it only because MultiMillerLoop depends on it.
        unreachable!()
    }
}

/// See the doc for [super::kzg_decider].
impl MultiMillerLoop for NearBn256 {
    type G2Prepared = G2Affine;

    type Result = Gt;

    fn multi_miller_loop(_terms: &[(&Self::G1Affine, &Self::G2Prepared)]) -> Self::Result {
        unreachable!()
    }
}
