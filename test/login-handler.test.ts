import {LoginHandler} from "../src/login-handler";
import {UserRepository} from "../src/repository/user-repository";
import {AuthService} from "../src/service/auth-service";
import {APIGatewayProxyEvent, Context} from "aws-lambda";

jest.mock("../src/service/auth-service", () => {
    return {
        AuthService: jest.fn().mockImplementation(() => ({
            constructor: jest.fn(),
            generateToken: jest.fn().mockImplementation(() => "test-token"),
        }))
    }})

describe('Login handler', () => {
    it('should handle a valid login request', async () => {
        const mockService: AuthService = new AuthService(jest.fn() as unknown as UserRepository)
        const handler = new LoginHandler(mockService)

        const result = await handler.handle({
            headers: {
                Authorization: 'Basic dGNiZW5raGFyZEBnbWFpbC5jb206MTIzNDU2Nzg='
            },
        } as unknown as APIGatewayProxyEvent, {} as Context)
        expect(result).toStrictEqual({
            "body": "{\"accessToken\":\"test-token\"}",
            "headers": {
                "Access-Control-Allow-Origin": "*"
            },
            "statusCode": 200
        })

    })
})