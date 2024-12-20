import {User} from "../model/user";
import {DocumentClient} from "aws-sdk/clients/dynamodb";
import {getEnv} from "@tcbenkhard/aws-utils";

export class UserRepository {
    private dynamodb: DocumentClient
    private TABLE_NAME = getEnv('USER_TABLE_NAME')

    constructor(dynamodb: DocumentClient) {
        this.dynamodb = dynamodb
    }

    async getByEmail(email: string): Promise<User|undefined> {
        const result = await this.dynamodb.get({
            TableName: this.TABLE_NAME,
            Key: {
                email: email
            }
        }).promise()
        return result.Item as User
    }

    async save(user: User) {
        await this.dynamodb.put({
            TableName: this.TABLE_NAME,
            Item: user
        }).promise()
    }
}
