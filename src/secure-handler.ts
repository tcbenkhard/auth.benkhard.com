import {APIGatewayProxyEvent, Context} from "aws-lambda";
import {wrapHandler} from "@tcbenkhard/aws-utils";

const secure = (event: APIGatewayProxyEvent, context: Context) => {
    return "Authorized"
}

export const handler = wrapHandler(secure)