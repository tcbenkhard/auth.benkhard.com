import {b_cdk, b_dynamodb, b_lambda} from '@tcbenkhard/benkhard-cdk'
import {Construct} from 'constructs';
import {aws_apigateway, aws_dynamodb, aws_secretsmanager, aws_ssm} from "aws-cdk-lib";
import {AccountPrincipal} from "aws-cdk-lib/aws-iam";

export class AuthBenkhardComStack extends b_cdk.Stack {
    constructor(scope: Construct, id: string) {
        super(scope, id, 'auth-benkhard-com');

        const privateKey = aws_secretsmanager.Secret.fromSecretNameV2(this, 'PrivateKey', '/benkhard/auth/private-key')
        privateKey.grantRead(this.serviceRole)
        const publicKey = aws_secretsmanager.Secret.fromSecretNameV2(this, 'PublicKey', '/benkhard/auth/public-key')
        publicKey.grantRead(this.serviceRole)

        const userTable = new b_dynamodb.Table(this, 'UserTable', {
            tableName: 'users',
            partitionKey: {
                name: 'email',
                type: aws_dynamodb.AttributeType.STRING
            }
        })

        const environment = {
            'USER_TABLE_NAME': userTable.tableName,
            "JWT_PUBLIC_KEY_SECRET_ID": "/benkhard/auth/public-key",
            "JWT_PRIVATE_KEY_SECRET_ID": "/benkhard/auth/private-key"
        }

        const registrationHandler = new b_lambda.NodejsFunction(this, 'RegistrationHandler', {
            functionName: 'registration-handler',
            entry: 'src/handlers.ts',
            handler: 'registrationHandler',
            environment
        })

        const loginHandler = new b_lambda.NodejsFunction(this, 'LoginHandler', {
            functionName: 'login-handler',
            entry: 'src/handlers.ts',
            handler: 'loginHandler',
            environment
        })

        const secureHandler = new b_lambda.NodejsFunction(this, 'SecureHandler', {
            functionName: 'secure-handler',
            entry: 'src/handlers.ts',
            handler: 'secureHandler',
            environment
        })

        const authorizerHandler = new b_lambda.NodejsFunction(this, 'AuthorizerHandler', {
            functionName: 'authorizer',
            entry: 'src/handlers.ts',
            handler: 'authorizerHandler',
            description: "Authorizer function for API Gateway",
            environment
        })

        authorizerHandler.grantInvoke(new AccountPrincipal(this.account))

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
        secureResource.addMethod('GET', new aws_apigateway.LambdaIntegration(secureHandler), {
            authorizer: new aws_apigateway.TokenAuthorizer(this, 'TokenAuthorizer', {
                handler: authorizerHandler,
                identitySource: 'method.request.header.Authorization',
            }),
            authorizationType: aws_apigateway.AuthorizationType.CUSTOM,
        })

        new aws_ssm.StringParameter(this, 'AuthorizerLambdaArnParameter', {
            parameterName: '/benkhard/auth/lambda-authorizer-arn',
            stringValue: authorizerHandler.functionArn
        })
    }
}
