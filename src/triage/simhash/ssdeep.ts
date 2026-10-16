/**
 * Clean-room ssdeep (context-triggered piecewise hash / SpamSum) over a whole
 * buffer, reconstructed from the published SpamSum algorithm description. No
 * GPL fuzzy.c code is used. The output is the canonical
 * `blocksize:hash1:hash2` digest.
 */

const BLOCKSIZE_MIN = 3;
const SPAMSUM_LENGTH = 64;
const ROLL_WINDOW = 7;
const HASH_INIT = 0x27;

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** SpamSum partial FNV table over the low six bits of each input byte. */
// prettier-ignore
const F_TABLE = Uint8Array.from([
  0x00, 0x13, 0x26, 0x39, 0x0c, 0x1f, 0x32, 0x05,
  0x18, 0x2b, 0x3e, 0x11, 0x24, 0x37, 0x0a, 0x1d,
  0x30, 0x03, 0x16, 0x29, 0x3c, 0x0f, 0x22, 0x35,
  0x08, 0x1b, 0x2e, 0x01, 0x14, 0x27, 0x3a, 0x0d,
  0x20, 0x33, 0x06, 0x19, 0x2c, 0x3f, 0x12, 0x25,
  0x38, 0x0b, 0x1e, 0x31, 0x04, 0x17, 0x2a, 0x3d,
  0x10, 0x23, 0x36, 0x09, 0x1c, 0x2f, 0x02, 0x15,
  0x28, 0x3b, 0x0e, 0x21, 0x34, 0x07, 0x1a, 0x2d,
]);

interface Rolling {
  readonly window: Uint8Array;
  h1: number;
  h2: number;
  h3: number;
  position: number;
}

const newRolling = (): Rolling => ({
  window: new Uint8Array(ROLL_WINDOW),
  h1: 0,
  h2: 0,
  h3: 0,
  position: 0,
});

/** Advance the 7-byte rolling hash by one input byte; returns the trigger value. */
const roll = (state: Rolling, byte: number): number => {
  const leaving = state.window[state.position] as number;
  state.h2 = state.h2 - state.h1 + ROLL_WINDOW * byte;
  state.h1 = state.h1 + byte - leaving;
  state.window[state.position] = byte;
  state.position = (state.position + 1) % ROLL_WINDOW;
  state.h3 = (((state.h3 << 5) >>> 0) ^ byte) >>> 0;
  return (state.h1 + state.h2 + state.h3) >>> 0;
};

/** Starting block size: the smallest power-of-two multiple of 3 that spans the input. */
const initialBlockSize = (length: number): number => {
  let blockSize = BLOCKSIZE_MIN;
  while (blockSize * SPAMSUM_LENGTH < length) blockSize *= 2;
  return blockSize;
};

interface Pass {
  /** First signature, excluding the final flush character. */
  readonly hash1: string;
  /** Second signature, excluding the final flush character. */
  readonly hash2: string;
  readonly blockHash1: number;
  readonly blockHash2: number;
  readonly lastChar1: string;
  readonly lastChar2: string;
  readonly lastRolling: number;
}

/** One full SpamSum pass over the buffer at a fixed block size. */
const spamsumPass = (bytes: Buffer, blockSize: number): Pass => {
  const rolling = newRolling();
  let blockHash1 = HASH_INIT;
  let blockHash2 = HASH_INIT;
  let hash1 = "";
  let hash2 = "";
  let lastChar1 = "";
  let lastChar2 = "";
  let rh = 0;
  for (const byte of bytes) {
    const low = byte & 0x3f;
    blockHash1 = (F_TABLE[blockHash1] as number) ^ low;
    blockHash2 = (F_TABLE[blockHash2] as number) ^ low;
    rh = roll(rolling, byte);
    if (rh % blockSize !== blockSize - 1) continue;
    lastChar1 = B64[blockHash1] as string;
    if (hash1.length < SPAMSUM_LENGTH - 1) {
      hash1 += lastChar1;
      blockHash1 = HASH_INIT;
      lastChar1 = "";
    }
    if (rh % (blockSize * 2) !== blockSize * 2 - 1) continue;
    lastChar2 = B64[blockHash2] as string;
    if (hash2.length < SPAMSUM_LENGTH / 2 - 1) {
      hash2 += lastChar2;
      blockHash2 = HASH_INIT;
      lastChar2 = "";
    }
  }
  return {
    hash1,
    hash2,
    blockHash1,
    blockHash2,
    lastChar1,
    lastChar2,
    lastRolling: rh,
  };
};

/** Canonical ssdeep digest `blocksize:hash1:hash2` of the whole buffer. */
export const ssdeepHash = (bytes: Buffer): string => {
  let blockSize = initialBlockSize(bytes.length);
  for (;;) {
    const pass = spamsumPass(bytes, blockSize);
    // The halve decision uses the signature length before the final flush.
    if (blockSize > BLOCKSIZE_MIN && pass.hash1.length < SPAMSUM_LENGTH / 2) {
      blockSize = Math.floor(blockSize / 2);
      continue;
    }
    const tail1 =
      pass.lastRolling !== 0
        ? (B64[pass.blockHash1] as string)
        : pass.lastChar1;
    const tail2 =
      pass.lastRolling !== 0
        ? (B64[pass.blockHash2] as string)
        : pass.lastChar2;
    return `${blockSize}:${pass.hash1 + tail1}:${pass.hash2 + tail2}`;
  }
};
