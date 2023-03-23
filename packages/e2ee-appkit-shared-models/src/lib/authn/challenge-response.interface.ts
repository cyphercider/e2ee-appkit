export interface ChallengeResponseInterface {
  challengeText: string
  publicSigningKey: string
  encryptedPrivateSigningKey: string
  privateSigningKeyInitVector: string
  publicEncryptionKey: string
  encryptedPrivateEncryptionKey: string
  privateEncryptionKeyInitVector: string
  // additional response data from server if needed
  [key: string]: string
}
