//! Transcript for verifier on EVM.

use halo2_curves::bn256::{G1Affine, Fr};
use snark_verifier::{
    loader::{
        evm::{u256_to_fe, U256},
        Loader,
    },
    util::{
        arithmetic::{Coordinates, CurveAffine, PrimeField},
        transcript::{Transcript, TranscriptRead},
        // Itertools,
    },
    Error,
};
// use halo2_proofs::transcript::EncodedChallenge;
use std::{
    io::{self, Read},
    marker::PhantomData,
};

use near_sdk::env;

use super::loader::{
    NearLoader,
    LOADER,
    NearLoadedFr,
    NearLoadedG1,
};

/// Transcript for verifier using keccak256 as hasher. It computes hash
/// function using NEAR's precompiled contract [near_sys::keccak256].
///
/// This is mostly verbatim copy of
/// [EvmTranscript for NativeLoader](https://github.com/privacy-scaling-explorations/snark-verifier/blob/9feead7d4dbad951e6aa1d572230b1c098ec8040/snark-verifier/src/system/halo2/transcript/evm.rs#L175).
/// We only changed how its implementation computes hash.
#[derive(Debug)]
pub struct NearTranscript<C: CurveAffine, L: Loader<C>, S, B> {
    _loader: PhantomData<L>,
    stream: S,
    buf: B,
    _marker: PhantomData<C>,
}

impl<S> NearTranscript<G1Affine, NearLoader, S, Vec<u8>>
{
    /// Initialize [`NearTranscript`] given readable or writeable stream for
    /// verifying or proving with [`NearLoader`].
    pub fn new(stream: S) -> Self {
        Self {
            _loader: PhantomData,
            stream,
            buf: Vec::new(),
            _marker: PhantomData,
        }
    }
}

/// Native Keccak256 implementation that was used by
/// [snark_verifier::system::halo2::transcript::evm::EvmTranscript].

/// Keccak256 computation using NEAR precompiled contracts.
///
/// ```
///	use snark_verifier::util::hash::{Digest, Keccak256};
///	# use near_halo2_verifier::transcript::near_keccak256;
///
///	let v : Vec<u8> = "hello world".as_bytes().into();
///
///	assert_eq!(
///	  near_keccak256(&v),
///	  Into::<[u8;32]>::into(Keccak256::digest(&v)),
///	);
/// ```
pub fn near_keccak256(data: &Vec<u8>) -> [u8; 32] {
    env::keccak256_array(data)
}

impl<S> Transcript<G1Affine, NearLoader> for NearTranscript<G1Affine, NearLoader, S, Vec<u8>>
{
    fn loader(&self) -> &NearLoader {
        &LOADER
    }

    fn squeeze_challenge(&mut self) -> NearLoadedFr {
        let data : Vec<_> = self
            .buf
            .iter()
            .cloned()
            .chain(if self.buf.len() == 0x20 {
                Some(1)
            } else {
                None
            })
            .collect();
        let hash: [u8; 32] = near_keccak256(&data);
        self.buf = hash.to_vec();
        NearLoadedFr(u256_to_fe(U256::from_big_endian(hash.as_slice())))
    }

    fn common_ec_point(&mut self, ec_point: &NearLoadedG1) -> Result<(), Error> {
        let coordinates =
            Option::<Coordinates<G1Affine>>::from(ec_point.0.coordinates()).ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point".to_string(),
                )
            })?;

        [coordinates.x(), coordinates.y()].map(|coordinate| {
            self.buf
                .extend(coordinate.to_repr().as_ref().iter().rev().cloned());
        });

        Ok(())
    }

    fn common_scalar(&mut self, scalar: &NearLoadedFr) -> Result<(), Error> {
        self.buf.extend(scalar.0.to_repr().as_ref().iter().rev());

        Ok(())
    }
}

impl<S> TranscriptRead<G1Affine, NearLoader> for NearTranscript<G1Affine, NearLoader, S, Vec<u8>>
where
    S: Read,
{
    fn read_scalar(&mut self) -> Result<NearLoadedFr, Error> {
        let mut data = [0; 32];
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        data.reverse();
        let scalar = Fr::from_repr_vartime(data).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Invalid scalar encoding in proof".to_string(),
            )
        })?;
        let s = NearLoadedFr(scalar);
        self.common_scalar(&s)?;
        Ok(s)
    }

    fn read_ec_point(&mut self) -> Result<NearLoadedG1, Error> {
        let [mut x, mut y] = [<<G1Affine as CurveAffine>::Base as PrimeField>::Repr::default(); 2];
        for repr in [&mut x, &mut y] {
            self.stream
                .read_exact(repr.as_mut())
                .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
            repr.as_mut().reverse();
        }
        let x = Option::from(<<G1Affine as CurveAffine>::Base as PrimeField>::from_repr(x));
        let y = Option::from(<<G1Affine as CurveAffine>::Base as PrimeField>::from_repr(y));
        let ec_point = x
            .zip(y)
            .and_then(|(x, y)| Option::from(G1Affine::from_xy(x, y).map(|p| NearLoadedG1(p))))
            .ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point encoding in proof".to_string(),
                )
            })?;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}
