#![feature(iterator_try_collect)]

pub mod loader;
pub mod transcript;
pub mod multi_miller_loop;
pub mod kzg_decider;
mod util;

pub use halo2_curves::bn256;

use borsh::{BorshDeserialize, BorshSerialize};
use halo2_curves::bn256::{Fr, G1Affine, Bn256};
use halo2_proofs::{plonk::VerifyingKey, poly::{kzg::commitment::ParamsKZG, commitment::ParamsProver}};
use snark_verifier::{
    pcs::kzg::{Gwc19, KzgAs, KzgDecidingKey},
    verifier::{
        self,
        SnarkVerifier,
        plonk::PlonkProtocol,
    }, system::halo2::compile,
};

use crate::{
    loader::{
        NearLoader,
        NearLoadedFr,
    },
    transcript::NearTranscript,
    multi_miller_loop::NearBn256,
};

type PlonkVerifier =
    snark_verifier::verifier::plonk::PlonkVerifier<KzgAs<NearBn256, Gwc19>>;

/// This value contains both verifier key and circuit-dependent precomputed data.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct PlonkVerifierData {
    pub kzg_dk: KzgDecidingKey<NearBn256>,
    pub protocol: PlonkProtocol<G1Affine, NearLoader>,
}

impl PlonkVerifierData {
    /// This creates PlonkVerifierData from paramters and verifier key used by
    /// traditional halo2 prover. Useful if you want to connect `plonk_verify` in
    /// place of halo2_proofs verifier.
    ///
    /// It fixed the number of verified circuits batch size to 1.
    pub fn new(
        params: ParamsKZG<Bn256>,
        ver_key: VerifyingKey<G1Affine>,
        num_instance: usize,
    ) -> Self {
        let loader = NearLoader;
        let protocol = compile(
            &params,
            &ver_key,
            snark_verifier::system::halo2::Config::kzg()
                .set_zk(true)
                .with_num_proof(1)
                .with_num_instance(vec![num_instance]),
        ).loaded(&loader);
        let kzg_dk = (params.get_g()[0], params.g2(), params.s_g2()).into();
        PlonkVerifierData { kzg_dk, protocol }
    }
}

/// Verify a circuit specified by the [PlonkVerifierData] paramter.
pub fn plonk_verify(
    plonk_vk: &PlonkVerifierData,
    inputs: Vec<Fr>,
    proof: Vec<u8>,
) -> bool {
    let PlonkVerifierData { kzg_dk, protocol } = plonk_vk;

    dbg!(inputs.len());
    dbg!(&protocol.num_instance);

    let mut transcript = NearTranscript::<_, NearLoader, _, _>::new(proof.as_slice());

    let inputs_w = [inputs.into_iter().map(|x| NearLoadedFr(x)).collect()];
    let inputs = inputs_w.as_slice();
    let proof = PlonkVerifier::read_proof(kzg_dk, &protocol, inputs, &mut transcript).unwrap();
    let res = PlonkVerifier::verify(kzg_dk, &protocol, inputs, &proof);

    res.is_ok()
}
