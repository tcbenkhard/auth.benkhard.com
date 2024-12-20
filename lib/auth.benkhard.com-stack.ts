import {b_cdk, b_lambda, b_dynamodb} from '@tcbenkhard/benkhard-cdk'
import {Construct} from 'constructs';
import {aws_dynamodb} from "aws-cdk-lib";

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

    const registration_handler = new b_lambda.NodejsFunction(this, 'RegistrationHandler', {
      functionName: 'registration-handler',
      entry: 'src/registration-handler.ts',
      handler: 'handler',
      environment: {
        'USER_TABLE_NAME': userTable.tableName
      }
    })
  }
}
