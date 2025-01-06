import {APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context} from "aws-lambda";
import {AuthService} from "./service/auth-service";

export const buildAuthorizer = (authService: AuthService) => async (event: APIGatewayTokenAuthorizerEvent, context: Context): Promise<APIGatewayAuthorizerResult> => {
    try {
        console.info("Authorizing", event)
        const payload = await authService.validateToken(event.authorizationToken.substring("Bearer ".length))
        console.info("Authorized")
        return {
            principalId: "user",
            policyDocument: {
                Version: "2012-10-17",
                Statement: [
                    {
                        Action: "execute-api:Invoke",
                        Effect: "Allow",
                        Resource: "*"
                    }
                ]
            },
            context: {
                user: `${payload.sub}`
            }
        }
    } catch (e) {
        console.info("Unauthorized", e)
        return {
            principalId: "user",
            policyDocument: {
                Version: "2012-10-17",
                Statement: [
                    {
                        Action: "execute-api:Invoke",
                        Effect: "Deny",
                        Resource: "*"
                    }
                ]
            }
        }
    }
}