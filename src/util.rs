use halo2_curves::bn256::{G1Affine, Fr, G2Affine, Fq};
use near_sdk::env;

#[inline]
pub fn alt_bn128_g1_multiexp(v: &[(G1Affine, Fr)]) -> G1Affine {
    let mut data = Vec::with_capacity(core::mem::size_of::<(G1Affine, Fr)>() * v.len());
    for (g1, fr) in v {
        data.extend_from_slice(
            g1.x.to_bytes()
                .as_slice(),
        );
        data.extend_from_slice(
            g1.y.to_bytes()
                .as_slice(),
        );
        data.extend_from_slice(
            fr.to_bytes()
                .as_slice(),
        );
    }

    let res = env::alt_bn128_g1_multiexp(&data);
    G1Affine {
        x: Fq::from_bytes(res[0..32].try_into().unwrap()).unwrap(),
        y: Fq::from_bytes(res[32..64].try_into().unwrap()).unwrap(),
    }
}

#[inline]
pub fn alt_bn128_pairing_check(v: Vec<(G1Affine, G2Affine)>) -> bool {
    let mut data = Vec::with_capacity(core::mem::size_of::<(G1Affine, Fr)>() * v.len());

    for (g1, g2) in v {
        for f in [g1.x, g1.y, g2.x.c0, g2.x.c1, g2.y.c0, g2.y.c1] {
            data.extend_from_slice(
                f.to_bytes()
                 .as_slice(),
            );
        }
    }

    env::alt_bn128_pairing_check(&data)
}
