//! `Loader` implementation in native rust.

use borsh::{BorshSerialize, BorshDeserialize};
use halo2_curves::bn256::{Fr, G1Affine};
use snark_verifier::{
    loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader},
    util::arithmetic::FieldOps,
    Error,
};
use lazy_static::lazy_static;
use std::fmt::Debug;

lazy_static! {
    /// NearLoader instance for [`LoadedEcPoint::loader`] and
    /// [`LoadedScalar::loader`] referencing.
    pub static ref LOADER: NearLoader = NearLoader;
}

extern crate derive_more;
use derive_more::{Add, AddAssign, Sub, SubAssign};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::util::alt_bn128_g1_multiexp;

/// This type is used as [LoadedScalar] for our [NearLoader].
///
/// For [snark_verifier], this value serves as an abstract variable referring
/// to an [Fr] that is used to build a circuit. In this case, we directly keep
/// the [Fr] referred to inside (but [snark_verifier] doesn't know that, it
/// only accesses this type through [LoadedScalar] interface).
///
/// We bypass all the arithmetic operations to the internal [Fr].
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Add, AddAssign, Sub, SubAssign)]
pub struct NearLoadedFr(pub Fr);

#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NearLoadedG1(pub G1Affine);

/// Loader that offloads pairing and multiexp operations to NEAR precompiled contracts.
/// It's based on [snark_verifier::loader::native::NativeLoader].
#[derive(Clone, Debug)]
pub struct NearLoader;

impl<'a> MulAssign<&'a NearLoadedFr> for NearLoadedFr {
    fn mul_assign(&mut self, other: &NearLoadedFr) {
        self.0.mul_assign(other.0)
    }
}

impl MulAssign<NearLoadedFr> for NearLoadedFr {
    fn mul_assign(&mut self, other: NearLoadedFr) {
        self.0.mul_assign(other.0)
    }
}

impl<'a> SubAssign<&'a NearLoadedFr> for NearLoadedFr {
    fn sub_assign(&mut self, other: &NearLoadedFr) {
        self.0.sub_assign(other.0)
    }
}

impl<'a> AddAssign<&'a NearLoadedFr> for NearLoadedFr {
    fn add_assign(&mut self, other: &NearLoadedFr) {
        self.0.add_assign(other.0)
    }
}

impl<'a> Mul<&'a NearLoadedFr> for NearLoadedFr {
    type Output = NearLoadedFr;

    fn mul(self, other: &NearLoadedFr) -> NearLoadedFr {
        NearLoadedFr(self.0.mul(other.0))
    }
}

impl Mul<NearLoadedFr> for NearLoadedFr {
    type Output = NearLoadedFr;

    fn mul(self, other: NearLoadedFr) -> NearLoadedFr {
        NearLoadedFr(self.0.mul(other.0))
    }
}

impl<'a> Sub<&'a NearLoadedFr> for NearLoadedFr {
    type Output = NearLoadedFr;

    fn sub(self, other: &NearLoadedFr) -> NearLoadedFr {
        NearLoadedFr(self.0.sub(other.0))
    }
}

impl<'a> Add<&'a NearLoadedFr> for NearLoadedFr {
    type Output = NearLoadedFr;

    fn add(self, other: &NearLoadedFr) -> NearLoadedFr {
        NearLoadedFr(self.0.add(other.0))
    }
}

impl Neg for NearLoadedFr {
    type Output = NearLoadedFr;

    fn neg(self) -> NearLoadedFr {
        NearLoadedFr(self.0.neg())
    }
}

impl LoadedEcPoint<G1Affine> for NearLoadedG1 {
    type Loader = NearLoader;

    fn loader(&self) -> &NearLoader {
        &LOADER
    }
}

impl FieldOps for NearLoadedFr {
    fn invert(&self) -> Option<NearLoadedFr> {
        FieldOps::invert(&self.0).map(|x| NearLoadedFr(x)).into()
    }
}

impl LoadedScalar<Fr> for NearLoadedFr {
    type Loader = NearLoader;

    fn loader(&self) -> &NearLoader {
        &LOADER
    }
}

impl EcPointLoader<G1Affine> for NearLoader {
    type LoadedEcPoint = NearLoadedG1;

    fn ec_point_load_const(&self, value: &G1Affine) -> Self::LoadedEcPoint {
        NearLoadedG1(*value)
    }

    fn ec_point_assert_eq(
        &self,
        annotation: &str,
        lhs: &Self::LoadedEcPoint,
        rhs: &Self::LoadedEcPoint,
    ) -> Result<(), Error> {
        lhs.eq(rhs)
            .then_some(())
            .ok_or_else(|| Error::AssertionFailure(annotation.to_string()))
    }

    fn multi_scalar_multiplication(
        pairs: &[(&NearLoadedFr, &NearLoadedG1)],
    ) -> NearLoadedG1 {
        let pairs : Vec<_> = pairs
            .into_iter()
            .map(|(NearLoadedFr(scalar), NearLoadedG1(g))| (g.clone(), (*scalar)))
            .collect();
        let res = alt_bn128_g1_multiexp(&pairs);
        NearLoadedG1(res)
    }
}


/// [ScalarLoader] has more methods with default implementations, one
/// can re-define more operations using them. [ScalarLoader::product],
/// [ScalarLoader::batch_invert].
impl ScalarLoader<Fr> for NearLoader {
    type LoadedScalar = NearLoadedFr;

    fn load_const(&self, value: &Fr) -> Self::LoadedScalar {
        NearLoadedFr(*value)
    }

    fn assert_eq(
        &self,
        annotation: &str,
        lhs: &Self::LoadedScalar,
        rhs: &Self::LoadedScalar,
    ) -> Result<(), Error> {
        lhs.eq(rhs)
            .then_some(())
            .ok_or_else(|| Error::AssertionFailure(annotation.to_string()))
    }
}

impl Loader<G1Affine> for NearLoader {}
