import {AuthService} from "./service/auth-service";
import {z} from "zod";
import {ServerError, wrapHandler} from "@tcbenkhard/aws-utils";
import {APIGatewayProxyEvent, Context} from "aws-lambda";

const authService = AuthService.build()

const LoginRequestSchema = z.object({
    email: z.string().email(),
    password: z.string(),
})

const decode = (str: string):string => Buffer.from(str, 'base64').toString('binary');

export type LoginRequest = z.infer<typeof LoginRequestSchema>

const loginHandler = (event: APIGatewayProxyEvent, context: Context) => {
    console.info(event)
    const authHeader = event.headers['Authorization']
    if(!authHeader) {
        throw ServerError.unauthorized("INVALID_CREDENTIALS", "Username or password is incorrect")
    }
    const decodedHeader = decode(authHeader.substring('Basic '.length));
    const headerValues = decodedHeader.split(':');
    const request = LoginRequestSchema.parse({
        email: headerValues[0],
        password: headerValues[1]
    })
    return authService.generateToken(request)
}

export const handler = wrapHandler(loginHandler, 200)