//! `Loader` implementation in native rust.

use borsh::{BorshSerialize, BorshDeserialize};
use ff_uint::Uint;
use halo2_curves::{bn256::{Fr, Fq, Fq2, G1Affine, G2Affine}, serde::SerdeObject};
use snark_verifier::{
    loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader},
    util::arithmetic::{Curve, CurveAffine, FieldOps, PrimeField},
    Error,
};
use lazy_static::lazy_static;
use std::{fmt::Debug, alloc::GlobalAlloc};

lazy_static! {
    /// NearLoader instance for [`LoadedEcPoint::loader`] and
    /// [`LoadedScalar::loader`] referencing.
    pub static ref LOADER: NearLoader = NearLoader;
}

extern crate derive_more;
use derive_more::{Add, AddAssign, Sub, SubAssign};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use crate::verifiers::util::{
    alt_bn128_g1_multiexp,
    Fr as NearFr,
    Fq as NearFq,
    G1 as NearG1,
    G2 as NearG2,
};

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

/// Convert halo2's Fr representation into format used by NEAR precompiled
/// contracts.
pub fn fr_from_near(v: NearFr) -> Fr {
    Fr::from_bytes(&v.to_little_endian().try_into().unwrap()).unwrap()
}

/// Convert Fr from NEAR's precompiled contract representation into halo2's.
pub fn fr_into_near(v: &Fr) -> NearFr {
    NearFr::from_little_endian(&v.to_bytes())
}

impl From<NearFr> for NearLoadedFr {
    fn from(v: NearFr) -> Self {
        NearLoadedFr(fr_from_near(v))
    }
}

impl Into<NearFr> for &NearLoadedFr {
    fn into(self) -> NearFr {
        fr_into_near(&self.0)
    }
}

/// Convert halo2's Fq representation into format used by NEAR precompiled
/// contracts.
pub fn fq_from_near(v: NearFq) -> Fq {
    Fq::from_bytes(&v.to_little_endian().try_into().unwrap()).unwrap()
}

/// Convert Fq from NEAR's precompiled contract representation into halo2's.
pub fn fq_into_near(v: &Fq) -> NearFq {
    NearFq::from_little_endian(&v.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::num::uint_from_u64;

    #[test]
    fn test_fq_conv_inv() {
        let v : Fq = (0xdeadbeef as u64).into();
        let u : NearFq = uint_from_u64(0xdeadbeef);

        {
            let u_ = fq_from_near(u);
            assert_eq!(&v, &u_);
        }
        {
            let v_ = fq_into_near(&v);
            assert_eq!(&u, &v_);
        }
    }
}

#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct NearLoadedG1(pub G1Affine);

/// From NEAR precompiled contract representation to halo2's
pub fn g1_from_near([x, y]: NearG1) -> G1Affine {
    let x = fq_from_near(x);
    let y = fq_from_near(y);
    G1Affine {
        x: x.into(),
        y: y.into(),
    }
}

/// From halo2 representation into NEAR precompiled contract
pub fn g1_into_near(G1Affine { x, y }: &G1Affine) -> NearG1 {
    [fq_into_near(x), fq_into_near(y)]
}

/// Convert representation of [alt_bn128_pairing_check] into halo2's.
pub fn g2_from_near([x_c0, x_c1, y_c0, y_c1]: NearG2) -> G2Affine {
    // x_real, x_im, y_real, y_im
    //
    // c_0 - real, c1 - im
    G2Affine {
        x: Fq2 { c0: fq_from_near(x_c0), c1: fq_from_near(x_c1) },
        y: Fq2 { c0: fq_from_near(y_c0), c1: fq_from_near(y_c1) },
    }
}

/// Convert halo2's representation into one compatible with [alt_bn128_pairing_check].
pub fn g2_into_near(G2Affine { x, y }: &G2Affine) -> NearG2 {
    [
        fq_into_near(&x.c0),
        fq_into_near(&x.c1),
        fq_into_near(&y.c0),
        fq_into_near(&y.c1),
    ]
}

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
            .map(|(scalar, NearLoadedG1(g))| (g1_into_near(g), (*scalar).into()))
            .collect();
        let res = alt_bn128_g1_multiexp(&pairs);
        NearLoadedG1(g1_from_near(res))
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
