import {RegistrationHandler} from "../src/registration-handler";
import {AuthService} from "../src/service/auth-service";
import {APIGatewayProxyEvent, Context} from "aws-lambda";
import {UserRepository} from "../src/repository/user-repository";

jest.mock("../src/service/auth-service", () => ({
    AuthService: jest.fn().mockImplementation(() => ({
        constructor: jest.fn(),
        registerUser: jest.fn().mockImplementation(() => ({
            email: 'test@test.com',
            name: 'Tester Test',
        }))
    }))
}))

describe('RegistrationHandler', () => {
    it('should handle a valid registration request', async () => {
        const mockService: AuthService = new AuthService(jest.fn() as unknown as UserRepository)
        const registrationHandler = new RegistrationHandler(mockService)
        const result = await registrationHandler.handle({body: JSON.stringify({
                password: '123',
                email: 'test@test.com',
                name: 'Tester Test'
            })} as APIGatewayProxyEvent, {} as Context)

        expect(result).toStrictEqual({
            "body": "{\"email\":\"test@test.com\",\"name\":\"Tester Test\"}",
            "headers": {
                "Access-Control-Allow-Origin": "*"
            },
            "statusCode": 201
        })
    })

    it('should return 400 when the request is invalid', async () => {
        const mockService: AuthService = new AuthService(jest.fn() as unknown as UserRepository)
        const registrationHandler = new RegistrationHandler(mockService)
        const result = await registrationHandler.handle({body: JSON.stringify({
                password: '123',
                name: 'Tester Test'
            })} as APIGatewayProxyEvent, {} as Context)
        expect(result).toStrictEqual({
            "body": "{\"statusCode\":400,\"errorCode\":\"INVALID_REQUEST_BODY\",\"errorMessage\":\"Failed to process request body\"}",
            "headers": {
                "Access-Control-Allow-Origin": "*"
            },
            "statusCode": 400
        })
    })
})