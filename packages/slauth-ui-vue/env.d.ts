/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

declare module '@cybersailor/slauth-ts' {
  export { AuthApi } from '../slauth-ts/dist/types/AuthApi'
  export { AdminApi } from '../slauth-ts/dist/types/AdminApi'
  export { createClients } from '../slauth-ts/dist/types/createClients'
  export * from '../slauth-ts/dist/types/lib/types'
  export * from '../slauth-ts/dist/types/lib/errors'
  export { version } from '../slauth-ts/dist/types/lib/version'
  export type {
    AdminUserResponse,
    AuthChangeEvent,
    ClientsConfig,
    ServiceConfig,
    Session,
    User,
  } from '../slauth-ts/dist/types/lib/types'

  import * as TypesNamespace from '../slauth-ts/dist/types/lib/types'
  export { TypesNamespace as Types }
}
