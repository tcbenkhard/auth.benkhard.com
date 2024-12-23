import {APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent, Context} from "aws-lambda";
import {AuthService} from "./service/auth-service";

const authService = AuthService.build()

const authorizer = (event: APIGatewayTokenAuthorizerEvent, context: Context): APIGatewayAuthorizerResult => {
    try {
        authService.validateToken(event.authorizationToken)
    } catch (e) {
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
}