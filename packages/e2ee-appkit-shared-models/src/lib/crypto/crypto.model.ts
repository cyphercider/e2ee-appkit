export interface KeyPair {
  publicKey: string
  privateKey: string
  gcmInitVector: string
}

export enum KeypairAlgorithm {
  Signing = 'RS256',
  Encrypting = 'RSA-OAEP-256',
}

export interface SignatureResult {
  signature: string
  protected: string
  payload: string
}
