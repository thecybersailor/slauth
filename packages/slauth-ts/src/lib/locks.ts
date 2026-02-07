type LockState = {
  tails: Map<string, Promise<void>>
}

const LOCK_STATE_SYMBOL = Symbol.for('@cybersailor/slauth-ts:lock-state')

function getLockState(): LockState {
  const globalAny = globalThis as any
  if (!globalAny[LOCK_STATE_SYMBOL]) {
    globalAny[LOCK_STATE_SYMBOL] = { tails: new Map<string, Promise<void>>() } satisfies LockState
  }
  return globalAny[LOCK_STATE_SYMBOL] as LockState
}

async function withInProcessExclusiveLock<T>(lockKey: string, fn: () => Promise<T>): Promise<T> {
  const state = getLockState()
  const previous = state.tails.get(lockKey) ?? Promise.resolve()

  let release!: () => void
  const current = new Promise<void>((resolve) => {
    release = resolve
  })

  state.tails.set(lockKey, previous.then(() => current))

  await previous
  try {
    return await fn()
  } finally {
    release()
    if (state.tails.get(lockKey) === current) {
      state.tails.delete(lockKey)
    }
  }
}

export async function withBestEffortExclusiveLock<T>(lockKey: string, fn: () => Promise<T>): Promise<T> {
  const navigatorAny = (globalThis as any).navigator
  const locks = navigatorAny?.locks
  const request = locks?.request

  if (typeof request === 'function') {
    // Web Locks API supports: request(name, callback) or request(name, options, callback)
    if (request.length >= 3) {
      return request.call(locks, lockKey, { mode: 'exclusive' }, fn)
    }
    return request.call(locks, lockKey, fn)
  }

  // Node/Bun fallback: in-process async mutex (does not coordinate across processes)
  return withInProcessExclusiveLock(lockKey, fn)
}
