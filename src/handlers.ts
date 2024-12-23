import {wrapHandler} from "@tcbenkhard/aws-utils";
import {AuthService} from "./service/auth-service";
import {buildLoginHandler} from "./login-handler";
const authService =  AuthService.build()
export const loginHandler = wrapHandler(buildLoginHandler(authService), 200)