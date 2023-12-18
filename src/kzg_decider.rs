use halo2_curves::bn256::{G1Affine, Bn256};
use snark_verifier::{
    pcs::{
        kzg::{KzgAccumulator, KzgAs, KzgDecidingKey},
        AccumulationDecider,
    },
    Error,
};
use std::fmt::Debug;

use crate::verifiers::util::alt_bn128_pairing_check;

use super::{
    loader::{NearLoader, g1_into_near, g2_into_near},
    multi_miller_loop::NearBn256,
};

/// This is where we offload MultiMillerLoop to NEAR's precompiled contract.
impl<MOS> AccumulationDecider<G1Affine, NearLoader> for KzgAs<NearBn256, MOS>
where
    MOS: Clone + Debug,
{
    type DecidingKey = KzgDecidingKey<NearBn256>;

    fn decide(
        dk: &Self::DecidingKey,
        KzgAccumulator { lhs, rhs }: KzgAccumulator<G1Affine, NearLoader>,
    ) -> Result<(), Error> {
        let terms = [(&lhs.0, &dk.g2.into()), (&rhs.0, &(-dk.s_g2).into())];
        alt_bn128_pairing_check(
            terms.iter()
                 .map(
                     |(&g1, &g2)|
                     (g1_into_near(&g1), g2_into_near(&g2))
                 )
                 .collect()
        )
        .then_some(())
        .ok_or_else(|| Error::AssertionFailure("e(lhs, g2)·e(rhs, -s_g2) == O".to_string()))
    }

    fn decide_all(
        dk: &Self::DecidingKey,
        accumulators: Vec<KzgAccumulator<G1Affine, NearLoader>>,
    ) -> Result<(), Error> {
        accumulators
            .into_iter()
            .map(|accumulator| Self::decide(dk, accumulator))
            .try_collect::<_>()?;
        Ok(())
    }
}
