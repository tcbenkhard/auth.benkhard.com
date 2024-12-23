import {APIGatewayProxyEvent, Context} from "aws-lambda";
import {AuthService} from "./service/auth-service";
import {z} from "zod";
import {parseBody, wrapHandler} from "@tcbenkhard/aws-utils";

const authService = AuthService.build()

export const RegistrationRequestSchema = z.object({
    email: z.string().email(),
    name: z.string(),
    password: z.string(),
})

export type RegistrationRequest = z.infer<typeof RegistrationRequestSchema>

const registration_handler = async (event: APIGatewayProxyEvent, context: Context) => {
    const request = parseBody(event.body, RegistrationRequestSchema)
    return await authService.registerUser(request)
}

export const handler = wrapHandler(registration_handler, 201)

