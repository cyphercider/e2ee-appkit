import { AllKeys } from './all-keys.interface'

export interface SignupInterfaceWithoutDynamic extends AllKeys {
  username: string
  alternateUsername?: string
}

export interface SignupInterface extends SignupInterfaceWithoutDynamic {
  [key: string]: string
}
