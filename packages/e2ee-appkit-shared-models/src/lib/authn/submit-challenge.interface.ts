export interface SubmitChallengeInterface {
  username: string
  protected: string
  challengeText: string
  signature: string
}

export interface SubmitChallengeInterfaceWithServerSignature extends SubmitChallengeInterface {
  serverSignature: string
  serverProtected: string
}
