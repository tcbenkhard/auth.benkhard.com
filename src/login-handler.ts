import {AuthService} from "./service/auth-service";
import {z} from "zod";
import {ServerError} from "@tcbenkhard/aws-utils";
import {APIGatewayProxyEvent} from "aws-lambda";
import {BaseHandler} from "@tcbenkhard/aws-utils/dist/lambda";

const LoginRequestSchema = z.object({
    email: z.string().email(),
    password: z.string(),
})

const decode = (str: string):string => Buffer.from(str, 'base64').toString('binary');

export type LoginRequest = z.infer<typeof LoginRequestSchema>

interface LoginResponse {
    accessToken: string,
}

export class LoginHandler extends BaseHandler<LoginRequest, LoginResponse> {

    constructor(private authService: AuthService) {
        super(200);
    }

    async parseEvent(event: APIGatewayProxyEvent): Promise<LoginRequest> {
        const authHeader = event.headers['Authorization']
        if(!authHeader) {
            throw ServerError.unauthorized("INVALID_CREDENTIALS", "Username or password is incorrect")
        }
        const decodedHeader = decode(authHeader.substring('Basic '.length));
        const headerValues = decodedHeader.split(':');
        return LoginRequestSchema.parse({
            email: headerValues[0],
            password: headerValues[1]
        })
    }

    async handleRequest(request: LoginRequest): Promise<LoginResponse> {
        const accessToken = await this.authService.generateToken(request)
        return {
            accessToken
        }
    }

}