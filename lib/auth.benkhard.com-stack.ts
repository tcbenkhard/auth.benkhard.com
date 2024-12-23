import {b_cdk, b_lambda, b_dynamodb} from '@tcbenkhard/benkhard-cdk'
import {Construct} from 'constructs';
import {aws_dynamodb, aws_apigateway} from "aws-cdk-lib";

export class AuthBenkhardComStack extends b_cdk.Stack {
  constructor(scope: Construct, id: string) {
    super(scope, id, 'auth-benkhard-com');

    const userTable = new b_dynamodb.Table(this, 'UserTable', {
      tableName: 'users',
      partitionKey: {
        name: 'email',
        type: aws_dynamodb.AttributeType.STRING
      }
    })

    const environment = {
      'USER_TABLE_NAME': userTable.tableName
    }

    const registrationHandler = new b_lambda.NodejsFunction(this, 'RegistrationHandler', {
      functionName: 'registration-handler',
      entry: 'src/registration-handler.ts',
      handler: 'handler',
      environment
    })

    const loginHandler = new b_lambda.NodejsFunction(this, 'LoginHandler', {
      functionName: 'login-handler',
      entry: 'src/login-handler.ts',
      handler: 'handler',
      environment
    })

    const secureHandler = new b_lambda.NodejsFunction(this, 'SecureHandler', {
      functionName: 'secure-handler',
      entry: 'src/secure-handler.ts',
      handler: 'handler',
      environment
    })

    const authorizerHandler = new b_lambda.NodejsFunction(this, 'AuthorizerHandler', {
      functionName: 'authorizer',
      entry: 'src/authorizer.ts',
      handler: 'handler',
      description: "Authorizer function for API Gateway"
    })

    const apigw = new aws_apigateway.RestApi(this, 'ApiGateway', {
      restApiName: 'auth.benkhard.com',
      description: 'Auth API for *.benkhard.com',
      deployOptions: {
        stageName: 'prod',
      },
      defaultCorsPreflightOptions: {
        allowOrigins: aws_apigateway.Cors.ALL_ORIGINS,
      }
    })

    const oauthResource = apigw.root.addResource('oauth')
    const authorizeResource = oauthResource.addResource('authorize')
    const secureResource = oauthResource.addResource('secure')
    const registerResource = apigw.root.addResource('register')

    authorizeResource.addMethod('POST', new aws_apigateway.LambdaIntegration(loginHandler))
    registerResource.addMethod('POST', new aws_apigateway.LambdaIntegration(registrationHandler))
    secureResource.addMethod('GET', new aws_apigateway.LambdaIntegration(loginHandler), {
      authorizer: new aws_apigateway.TokenAuthorizer(this, 'TokenAuthorizer', {
        handler: authorizerHandler,
        identitySource: 'method.request.header.Authorization',
      }),
      authorizationType: aws_apigateway.AuthorizationType.CUSTOM,
    })

  }
}
