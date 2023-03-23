import { JWTPayload } from 'jose'

export interface TokenPayload extends JWTPayload {
  sub: string
  // Additional attributes in token if needed
  [key: string]: any
}
