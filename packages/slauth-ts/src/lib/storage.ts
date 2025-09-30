import { isBrowser, supportsLocalStorage } from './helpers'

/** Storage interface */
export interface SupportedStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

/** Memory storage implementation for non-browser environments */
class MemoryStorage implements SupportedStorage {
  private store: { [key: string]: string } = {}

  getItem(key: string): string | null {
    return this.store[key] || null
  }

  setItem(key: string, value: string): void {
    this.store[key] = value
  }

  removeItem(key: string): void {
    delete this.store[key]
  }

  clear(): void {
    this.store = {}
  }
}

/** Memory storage adapter instance */
export const memoryStorageAdapter = new MemoryStorage()

/** Get appropriate storage implementation */
export function getStorage(): SupportedStorage {
  if (isBrowser() && supportsLocalStorage()) {
    return localStorage
  }
  return memoryStorageAdapter
}

/** Storage manager for session persistence */
export class StorageManager {
  private storage: SupportedStorage
  private storageKey: string

  constructor(storage?: SupportedStorage, storageKey: string = 'aira.auth.token') {
    this.storage = storage || getStorage()
    this.storageKey = storageKey
  }

  /** Get session from storage */
  async getSession(): Promise<any | null> {
    try {
      const data = this.storage.getItem(this.storageKey)
      if (!data) return null
      
      const session = JSON.parse(data)
      
      // Check if session is expired
      if (session.expires_at && session.expires_at <= Math.floor(Date.now() / 1000)) {
        await this.removeSession()
        return null
      }
      
      return session
    } catch (error) {
      console.warn('[slauth] Failed to get session from storage:', error)
      return null
    }
  }

  /** Save session to storage */
  async saveSession(session: any): Promise<void> {
    try {
      const data = JSON.stringify(session)
      this.storage.setItem(this.storageKey, data)
    } catch (error) {
      console.warn('[slauth] Failed to save session to storage:', error)
    }
  }

  /** Remove session from storage */
  async removeSession(): Promise<void> {
    try {
      this.storage.removeItem(this.storageKey)
    } catch (error) {
      console.warn('[slauth] Failed to remove session from storage:', error)
    }
  }

  /** Get user from storage */
  async getUser(): Promise<any | null> {
    try {
      const userKey = `${this.storageKey}-user`
      const data = this.storage.getItem(userKey)
      if (!data) return null
      
      return JSON.parse(data)
    } catch (error) {
      console.warn('[slauth] Failed to get user from storage:', error)
      return null
    }
  }

  /** Save user to storage */
  async saveUser(user: any): Promise<void> {
    try {
      const userKey = `${this.storageKey}-user`
      const data = JSON.stringify(user)
      this.storage.setItem(userKey, data)
    } catch (error) {
      console.warn('[slauth] Failed to save user to storage:', error)
    }
  }

  /** Remove user from storage */
  async removeUser(): Promise<void> {
    try {
      const userKey = `${this.storageKey}-user`
      this.storage.removeItem(userKey)
    } catch (error) {
      console.warn('[slauth] Failed to remove user from storage:', error)
    }
  }

  /** Clear all auth data from storage */
  async clearAll(): Promise<void> {
    await this.removeSession()
    await this.removeUser()
  }

  /** Check if storage is available */
  isAvailable(): boolean {
    try {
      const testKey = '__aira_auth_test__'
      this.storage.setItem(testKey, 'test')
      this.storage.removeItem(testKey)
      return true
    } catch {
      return false
    }
  }
}
