import {APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context} from "aws-lambda";
import {AuthService} from "./service/auth-service";

const authService = AuthService.build()

export const authorizer = async (event: APIGatewayTokenAuthorizerEvent, context: Context): Promise<APIGatewayAuthorizerResult> => {
    try {
        console.info("Authorizing", event)
        await authService.validateToken(event.authorizationToken.substring("Bearer ".length))
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
            }
        }
    } catch (e) {
        console.info("Unauthorized")
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