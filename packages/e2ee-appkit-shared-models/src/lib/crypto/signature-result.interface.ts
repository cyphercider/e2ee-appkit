export interface SignatureResult {
  signature: string
  protected: string
}

export interface SignatureResultWithChallengeText extends SignatureResult {
  challengeText: string
}
