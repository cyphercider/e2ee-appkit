export interface IKeystore {
  get(key: string): string | null
  set(key: string, value: string, expiresAt: number): void
  delete(key: string): void
}
