import { AllKeys } from './all-keys.interface'

export interface SignupInterface extends AllKeys {
  username: string

  [key: string]: string
}
