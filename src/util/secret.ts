import {GetSecretValueCommand, SecretsManagerClient} from "@aws-sdk/client-secrets-manager";
import {getEnv, ServerError} from "@tcbenkhard/aws-utils";
import {Cacheable} from "typescript-cacheable";

export class SecretUtils {
    @Cacheable()
    public static getSecretClient() {
        return new SecretsManagerClient()
    }

    @Cacheable()
    public static async getSecretValue(secretId: string) {
        const client = await this.getSecretClient()
        const publicKey = await client.send(new GetSecretValueCommand({
            SecretId: secretId
        }))
        if (publicKey.SecretString === undefined) throw new ServerError(500, "UNEXPECTED_ERROR", "Something unexpected has happened.")
        return publicKey.SecretString
    }
}




