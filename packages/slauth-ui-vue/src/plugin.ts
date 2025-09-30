import type { App } from 'vue'
import Auth from './components/Auth.vue'
import SignIn from './components/SignIn.vue'
import SignUp from './components/SignUp.vue'
import MagicLink from './components/MagicLink.vue'
import ForgotPassword from './components/ForgotPassword.vue'
import UpdatePassword from './components/UpdatePassword.vue'
import VerifyOtp from './components/VerifyOtp.vue'
import SocialProviders from './components/SocialProviders.vue'
import Input from './components/ui/Input.vue'
import Button from './components/ui/Button.vue'
import Label from './components/ui/Label.vue'
import Message from './components/ui/Message.vue'
import Divider from './components/ui/Divider.vue'
import Anchor from './components/ui/Anchor.vue'

export interface AiraAuthUIPluginOptions {
  componentPrefix?: string
}

export default {
  install(app: App, options: AiraAuthUIPluginOptions = {}) {
    const prefix = options.componentPrefix || 'Aira'

    // Register main components
    app.component(`${prefix}Auth`, Auth)
    app.component(`${prefix}SignIn`, SignIn)
    app.component(`${prefix}SignUp`, SignUp)
    app.component(`${prefix}MagicLink`, MagicLink)
    app.component(`${prefix}ForgotPassword`, ForgotPassword)
    app.component(`${prefix}UpdatePassword`, UpdatePassword)
    app.component(`${prefix}VerifyOtp`, VerifyOtp)
    app.component(`${prefix}SocialProviders`, SocialProviders)

    // Register UI components
    app.component(`${prefix}Input`, Input)
    app.component(`${prefix}Button`, Button)
    app.component(`${prefix}Label`, Label)
    app.component(`${prefix}Message`, Message)
    app.component(`${prefix}Divider`, Divider)
    app.component(`${prefix}Anchor`, Anchor)
  }
}
