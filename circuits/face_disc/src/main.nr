// Face discriminator circuit: proves an image is a face.
//
// Inputs: 48x48 RGB image (private), image_commit (public).
// Output: 1-field public input (image_commit).
//
// Architecture: Conv[3->4->8->16->16] + x^2 + GAP + Linear(16->1)
//   scale=1000, kernel=4, stride=2, pad=1.
//
// Weights: disc_weights.json (from tools/landmark/weights/)
//
// The circuit asserts disc_score > 0, meaning the CNN classifies
// the input as a face. The image_commit binds this proof to the
// landmark_regions proof via the contract asserting equality.

use std::hash::poseidon2_permutation;

mod weights_disc;
use weights_disc::{
    DISC_CONV0_W, DISC_CONV0_B,
    DISC_CONV1_W, DISC_CONV1_B,
    DISC_CONV2_W, DISC_CONV2_B,
    DISC_CONV3_W, DISC_CONV3_B,
    DISC_LINEAR_W, DISC_LINEAR_B,
};

global SCALE: i64 = 1000;

// Poseidon2 sponge over 6912 image field elements (same as landmark_regions).
fn poseidon2_sponge_6912(elems: [Field; 6912]) -> Field {
    let mut state: [Field; 4] = [0, 0, 0, 0];
    for b in 0..2304 {
        state[0] = state[0] + elems[b * 3];
        state[1] = state[1] + elems[b * 3 + 1];
        state[2] = state[2] + elems[b * 3 + 2];
        state = poseidon2_permutation(state, 4);
    }
    state[0] = state[0] + 1;  // sentinel
    state = poseidon2_permutation(state, 4);
    state[0]
}

fn main(
    image: [Field; 6912],
) -> pub [Field; 1] {
    // 1. Convert pixels to scaled i64 [0,255] -> [0,1000]
    let mut pixels: [i64; 6912] = [0; 6912];
    for i in 0..6912 {
        pixels[i] = (image[i] as i64) * 1000 / 255;
    }

    // 2. Run disc tower
    let layer0 = conv_3_4(pixels, DISC_CONV0_W, DISC_CONV0_B);
    let layer1 = conv_4_8(layer0, DISC_CONV1_W, DISC_CONV1_B);
    let layer2 = conv_8_16(layer1, DISC_CONV2_W, DISC_CONV2_B);
    let layer3 = conv_16_16(layer2, DISC_CONV3_W, DISC_CONV3_B);

    // 3. Global average pool (3x3 = 9 elements per channel)
    let mut pooled: [i64; 16] = [0; 16];
    for c in 0..16 {
        let mut sum: i64 = 0;
        for s in 0..9 {
            sum += layer3[c * 9 + s];
        }
        pooled[c] = sum / 9;
    }

    // 4. Linear head: 16 -> 1
    let mut score: i64 = 0;
    for c in 0..16 {
        score += pooled[c] * DISC_LINEAR_W[c];
    }
    score = score / 1000 + DISC_LINEAR_B;

    // 5. Gate: score must be > 0 (face)
    assert(score > 0);

    // 6. Bind image to public commitment
    let image_commit = poseidon2_sponge_6912(image);

    [image_commit]
}

// ---- Disc tower (bit-exact to pixel-prize-infra) ----
fn conv_3_4(input: [i64; 6912], weights: [i64; 192], bias: [i64; 4]) -> [i64; 2304] {
    let mut out: [i64; 2304] = [0; 2304];
    for out_c in 0..4 {
        for out_y in 0..24 {
            for out_x in 0..24 {
                let mut acc: i64 = 0;
                for in_c in 0..3 {
                    for ky in 0..4 {
                        for kx in 0..4 {
                            let iy: i64 = (out_y as i64) * 2 + (ky as i64) - 1;
                            let ix: i64 = (out_x as i64) * 2 + (kx as i64) - 1;
                            if (iy >= 0) & (iy < 48) & (ix >= 0) & (ix < 48) {
                                let pi: u32 = in_c * 2304 + (iy as u32) * 48 + (ix as u32);
                                let wi: u32 = out_c * 48 + in_c * 16 + ky * 4 + kx;
                                acc += input[pi] * weights[wi];
                            }
                        }
                    }
                }
                acc = acc / 1000 + bias[out_c];
                acc = acc * acc / 1000;  // x^2 activation
                out[out_c * 576 + out_y * 24 + out_x] = acc;
            }
        }
    }
    out
}

fn conv_4_8(input: [i64; 2304], weights: [i64; 512], bias: [i64; 8]) -> [i64; 1152] {
    let mut out: [i64; 1152] = [0; 1152];
    for out_c in 0..8 {
        for out_y in 0..12 {
            for out_x in 0..12 {
                let mut acc: i64 = 0;
                for in_c in 0..4 {
                    for ky in 0..4 {
                        for kx in 0..4 {
                            let iy: i64 = (out_y as i64) * 2 + (ky as i64) - 1;
                            let ix: i64 = (out_x as i64) * 2 + (kx as i64) - 1;
                            if (iy >= 0) & (iy < 24) & (ix >= 0) & (ix < 24) {
                                let pi: u32 = in_c * 576 + (iy as u32) * 24 + (ix as u32);
                                let wi: u32 = out_c * 64 + in_c * 16 + ky * 4 + kx;
                                acc += input[pi] * weights[wi];
                            }
                        }
                    }
                }
                acc = acc / 1000 + bias[out_c];
                acc = acc * acc / 1000;
                out[out_c * 144 + out_y * 12 + out_x] = acc;
            }
        }
    }
    out
}

fn conv_8_16(input: [i64; 1152], weights: [i64; 2048], bias: [i64; 16]) -> [i64; 576] {
    let mut out: [i64; 576] = [0; 576];
    for out_c in 0..16 {
        for out_y in 0..6 {
            for out_x in 0..6 {
                let mut acc: i64 = 0;
                for in_c in 0..8 {
                    for ky in 0..4 {
                        for kx in 0..4 {
                            let iy: i64 = (out_y as i64) * 2 + (ky as i64) - 1;
                            let ix: i64 = (out_x as i64) * 2 + (kx as i64) - 1;
                            if (iy >= 0) & (iy < 12) & (ix >= 0) & (ix < 12) {
                                let pi: u32 = in_c * 144 + (iy as u32) * 12 + (ix as u32);
                                let wi: u32 = out_c * 128 + in_c * 16 + ky * 4 + kx;
                                acc += input[pi] * weights[wi];
                            }
                        }
                    }
                }
                acc = acc / 1000 + bias[out_c];
                acc = acc * acc / 1000;
                out[out_c * 36 + out_y * 6 + out_x] = acc;
            }
        }
    }
    out
}

fn conv_16_16(input: [i64; 576], weights: [i64; 4096], bias: [i64; 16]) -> [i64; 144] {
    let mut out: [i64; 144] = [0; 144];
    for out_c in 0..16 {
        for out_y in 0..3 {
            for out_x in 0..3 {
                let mut acc: i64 = 0;
                for in_c in 0..16 {
                    for ky in 0..4 {
                        for kx in 0..4 {
                            let iy: i64 = (out_y as i64) * 2 + (ky as i64) - 1;
                            let ix: i64 = (out_x as i64) * 2 + (kx as i64) - 1;
                            if (iy >= 0) & (iy < 6) & (ix >= 0) & (ix < 6) {
                                let pi: u32 = in_c * 36 + (iy as u32) * 6 + (ix as u32);
                                let wi: u32 = out_c * 256 + in_c * 16 + ky * 4 + kx;
                                acc += input[pi] * weights[wi];
                            }
                        }
                    }
                }
                acc = acc / 1000 + bias[out_c];
                acc = acc * acc / 1000;
                out[out_c * 9 + out_y * 3 + out_x] = acc;
            }
        }
    }
    out
}
