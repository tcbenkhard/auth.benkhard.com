import {APIGatewayProxyEvent, Context} from "aws-lambda";
import {wrapHandler} from "@tcbenkhard/aws-utils";

const secure = async (event: APIGatewayProxyEvent, context: Context) => {
    console.info(event)
    console.info(context)
    return `Authorized as ${event.requestContext.authorizer!.user}`
}

export const handler = wrapHandler(secure)