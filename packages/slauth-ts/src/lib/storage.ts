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
    console.log('[slauth:storage] StorageManager created', {
      storageKey: this.storageKey,
      storageType: this.storage.constructor.name,
      customStorage: !!storage,
      stackTrace: new Error().stack?.split('\n').slice(2, 4).join('\n')
    })
  }

  /** Get session from storage */
  async getSession(): Promise<any | null> {
    console.log('[slauth:storage] getSession - checking storage', {
      storageKey: this.storageKey,
      storageType: this.storage.constructor.name,
      allKeys: this.storage === localStorage ? Object.keys(localStorage) : 'N/A'
    })
    
    const data = this.storage.getItem(this.storageKey)
    console.log('[slauth:storage] getSession - data retrieved', { 
      storageKey: this.storageKey,
      hasData: !!data,
      dataLength: data?.length,
      dataPreview: data ? `${data.substring(0, 50)}...` : null
    })
    if (!data) return null
    
    const session = JSON.parse(data)
    console.log('[slauth:storage] Session parsed', {
      hasAccessToken: !!session.access_token,
      hasExpiresAt: !!session.expires_at,
      expiresAt: session.expires_at
    })
    
    if (session.expires_at && session.expires_at <= Math.floor(Date.now() / 1000)) {
      console.log('[slauth:storage] Session expired, removing')
      await this.removeSession()
      return null
    }
    
    return session
  }

  /** Save session to storage */
  async saveSession(session: any): Promise<void> {
    const data = JSON.stringify(session)
    console.log('[slauth:storage] saveSession - before setItem', {
      storageKey: this.storageKey,
      hasAccessToken: !!session.access_token,
      tokenPreview: session.access_token ? `${session.access_token.substring(0, 20)}...` : null,
      dataLength: data.length,
      storageType: this.storage.constructor.name
    })
    
    this.storage.setItem(this.storageKey, data)
    
    const verification = this.storage.getItem(this.storageKey)
    console.log('[slauth:storage] saveSession - after setItem verification', {
      storageKey: this.storageKey,
      saved: !!verification,
      dataMatch: verification === data,
      verificationLength: verification?.length
    })
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
