import {AuthService} from "./service/auth-service";
import {LoginHandler} from "./login-handler";
import {RegistrationHandler} from "./registration-handler";
import {handler as secure} from "./secure-handler";
import {buildAuthorizer} from "./authorizer";

const authService = AuthService.build()

export const loginHandler = new LoginHandler(authService).handle
export const registrationHandler = new RegistrationHandler(authService).handle
export const secureHandler = secure
export const authorizerHandler = buildAuthorizer(authService)