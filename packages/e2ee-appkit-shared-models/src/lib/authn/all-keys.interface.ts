export interface AllKeys {
  publicSigningKey: string
  encryptedPrivateSigningKey: string
  encryptedPrivateSigningKeyAlternate?: string
  // The iv that was used to wrap the private signing key with the user's password
  privateSigningKeyInitVector: string
  publicEncryptionKey: string
  encryptedPrivateEncryptionKey: string
  encryptedPrivateEncryptionKeyAlternate?: string
  // The iv that was used to wrap the private encryption key with the user's password
  privateEncryptionKeyInitVector: string
}
