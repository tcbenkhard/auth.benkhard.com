import {APIGatewayProxyEvent} from "aws-lambda";
import {AuthService} from "./service/auth-service";
import {z} from "zod";
import {parseBody} from "@tcbenkhard/aws-utils";
import {BaseHandler} from "@tcbenkhard/aws-utils/dist/lambda";

export const RegistrationRequestSchema = z.object({
    email: z.string().email(),
    name: z.string(),
    password: z.string(),
})

export type RegistrationRequest = z.infer<typeof RegistrationRequestSchema>

interface RegistrationResponse {
    email: string,
    name: string,
}

export class RegistrationHandler extends BaseHandler<RegistrationRequest, RegistrationResponse> {
    constructor(private authService: AuthService) {
        super(201);
    }

    async parseEvent(event: APIGatewayProxyEvent): Promise<RegistrationRequest> {
        return parseBody(event.body, RegistrationRequestSchema);
    }

    async handleRequest(request: RegistrationRequest): Promise<RegistrationResponse> {
        const user = await this.authService.registerUser(request);
        return {
            email: user.email,
            name: user.name,
        };
    }
}

