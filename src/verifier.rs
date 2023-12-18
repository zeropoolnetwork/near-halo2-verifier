use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use halo2_curves::{
    bn256::{Bn256, Fq, Fr, G1Affine},
};
use halo2_proofs::{
    plonk::{VerifyingKey, Circuit},
    poly::{
        commitment::{ParamsProver, Params},
        kzg::commitment::{ParamsKZG},
    }, SerdeFormat,
};
use snark_verifier::{
    pcs::kzg::{Gwc19, KzgAs, KzgDecidingKey},
    system::halo2::{compile, Config},
    verifier::{
        self,
        SnarkVerifier,
        plonk::PlonkProtocol,
    },
};

use super::{
    loader::{
        NearLoader,
        NearLoadedFr,
    },
    transcript::NearTranscript,
    multi_miller_loop::NearBn256,
    // kzg_decider::*,
};

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<NearBn256, Gwc19>>;

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct PlonkVerifierData {
    pub kzg_dk: KzgDecidingKey<NearBn256>,
    pub protocol: PlonkProtocol<G1Affine, NearLoader>,
}

/// The type parameter `C` is your circuit type
pub fn plonk_verify(
    plonk_vk: &PlonkVerifierData,
    inputs: Vec<Fr>,
    proof: Vec<u8>,
) -> bool {
    let PlonkVerifierData { kzg_dk, protocol } = plonk_vk;

    let mut transcript = NearTranscript::<_, NearLoader, _, _>::new(proof.as_slice());

    let inputs_w = [inputs.into_iter().map(|x| NearLoadedFr(x)).collect()];
    let inputs = inputs_w.as_slice();
    let proof = PlonkVerifier::read_proof(kzg_dk, &protocol, inputs, &mut transcript).unwrap();
    let res = PlonkVerifier::verify(kzg_dk, &protocol, inputs, &proof);

    res.is_ok()
}
