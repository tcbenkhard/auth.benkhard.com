import {APIGatewayProxyEvent, Context} from "aws-lambda";
import {buildLoginHandler} from '../src/login-handler'
import {AuthService} from "../src/service/auth-service";
import {mock} from "ts-mockito";

describe('Login handler', () => {

    it('should accept a valid login', () => {
        const handler = buildLoginHandler(mock(AuthService))
        handler({
            headers: {
                Authorization: 'Basic dGNiZW5raGFyZEBnbWFpbC5jb206MzNiNEY2MjFA',
            }
        } as unknown as APIGatewayProxyEvent, {} as unknown as Context)
    })
})