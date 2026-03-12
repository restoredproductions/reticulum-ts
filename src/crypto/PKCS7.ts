/**
 * PKCS#7 padding for AES-CBC.
 * Block size: 16 bytes (128-bit AES blocks).
 */

const BLOCK_SIZE = 16;

/** Add PKCS#7 padding to data */
export function pad(data: Uint8Array): Uint8Array {
  const paddingLen = BLOCK_SIZE - (data.length % BLOCK_SIZE);
  const padded = new Uint8Array(data.length + paddingLen);
  padded.set(data);
  for (let i = data.length; i < padded.length; i++) {
    padded[i] = paddingLen;
  }
  return padded;
}

/** Remove PKCS#7 padding from data. Throws on invalid padding. */
export function unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0) throw new Error('PKCS7: Cannot unpad empty data');
  if (data.length % BLOCK_SIZE !== 0) throw new Error('PKCS7: Data not block-aligned');

  const paddingLen = data[data.length - 1];
  if (paddingLen === 0 || paddingLen > BLOCK_SIZE) {
    throw new Error('PKCS7: Invalid padding byte');
  }

  // Verify all padding bytes
  for (let i = data.length - paddingLen; i < data.length; i++) {
    if (data[i] !== paddingLen) {
      throw new Error('PKCS7: Invalid padding');
    }
  }

  return data.slice(0, data.length - paddingLen);
}
