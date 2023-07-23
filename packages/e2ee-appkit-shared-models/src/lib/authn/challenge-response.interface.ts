export interface ServerChallengeResponse {
  challengeText: string
  publicSigningKey: string
  encryptedPrivateSigningKey: string
  // Encrypted with alternate key - used for password reset
  encryptedPrivateSigningKeyAlternate?: string
  privateSigningKeyInitVector: string
  publicEncryptionKey: string
  encryptedPrivateEncryptionKey: string
  // Encrypted with alternate key - used for password reset
  encryptedPrivateEncryptionKeyAlternate?: string
  privateEncryptionKeyInitVector: string
  // additional response data from server if needed
  [key: string]: string
}
