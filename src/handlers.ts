import {AuthService} from "./service/auth-service";
import {LoginHandler} from "./login-handler";
import {RegistrationHandler} from "./registration-handler";
import {handler as secure} from "./secure-handler";
import {buildAuthorizer} from "./authorizer";
import {APIGatewayProxyEvent, Context} from "aws-lambda";

const authService = AuthService.build()

const loginHandlerInstance = new LoginHandler(authService)
const registrationHandlerInstance = new RegistrationHandler(authService)

export const loginHandler = async (event: APIGatewayProxyEvent, context: Context) => {return await loginHandlerInstance.handle(event, context)}
export const registrationHandler = async (event: APIGatewayProxyEvent, context: Context) => {return await registrationHandlerInstance.handle(event, context)}
export const secureHandler = secure
export const authorizerHandler = buildAuthorizer(authService)