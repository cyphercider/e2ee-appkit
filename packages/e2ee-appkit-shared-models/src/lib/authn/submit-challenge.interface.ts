export interface SubmitChallengeInterface {
  username: string
  protected: string
  challengeText: string
  signature: string
  additionalPayloadFields?: Record<string, string>
}

export interface SubmitChallengeInterfaceWithServerSignature extends SubmitChallengeInterface {
  serverSignature: string
  serverProtected: string
}
