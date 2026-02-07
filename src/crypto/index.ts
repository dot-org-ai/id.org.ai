/**
 * Cryptographic primitives for id.org.ai
 *
 * Ed25519 agent keypairs for cryptographic identity:
 *   - Key generation, signing, and verification
 *   - DID format: did:agent:ed25519:{base58pubkey}
 *   - PEM encoding for .pub files
 *   - Base58 and Base64 encoding utilities
 */

export {
  // Key generation
  generateKeypair,

  // Signing and verification
  sign,
  verify,
  signMessage,
  verifyMessage,
  verifyFromDID,

  // DID conversion
  publicKeyToDID,
  didToPublicKey,
  isValidDID,

  // PEM encoding
  publicKeyToPEM,
  pemToPublicKey,

  // Base58 encoding
  base58Encode,
  base58Decode,

  // Base64 encoding
  base64Encode,
  base64Decode,
} from './keys'
