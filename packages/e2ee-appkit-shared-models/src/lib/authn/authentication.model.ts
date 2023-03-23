export interface SubmitChallengeInterface {
  username: string
  protected: string
  challengeText: string
  signature: string
}

export class LoginResponseInterface {
  challengeText: string
  publicSigningKey: string
  encryptedPrivateSigningKey: string
  privateSigningKeyInitVector: string
  publicEncryptionKey: string
  encryptedPrivateEncryptionKey: string
  privateEncryptionKeyInitVector: string
}

export interface LoginRequestInterface {
  username: string
}

export interface UserInterface {
  username: string
  publicSigningKey: string
  encryptedPrivateSigningKey: string
  privateSigningKeyInitVector: string
  publicEncryptionKey: string
  encryptedPrivateEncryptionKey: string
  privateEncryptionKeyInitVector: string
}

export interface SignupInterface {
  username: string
  publicSigningKey: string
  encryptedPrivateSigningKey: string
  // The iv that was used to wrap the private signing key with the user's password
  privateSigningKeyInitVector: string
  publicEncryptionKey: string
  encryptedPrivateEncryptionKey: string
  // The iv that was used to wrap the private encryption key with the user's password
  privateEncryptionKeyInitVector: string
  // additional data to pass to server if needed
  [key: string]: string
}
