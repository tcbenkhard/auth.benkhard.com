import * as crypto from "node:crypto";
import {UserRepository} from "../repository/user-repository";
import {pbkdf2Sync} from "pbkdf2";
import {User} from "../model/user";
import {RegistrationRequest} from "../registration-handler";
import {ServerError} from "@tcbenkhard/aws-utils";
import {LoginRequest} from "../login-handler";
import * as jwt from "jsonwebtoken";

export class AuthService {
    private userRepository: UserRepository

    constructor(userRepository: UserRepository) {
        this.userRepository = userRepository
    }

    registerUser = async (request: RegistrationRequest): Promise<User> => {
        const existingUser = await this.userRepository.getByEmail(request.email)
        if (existingUser) throw ServerError.badRequest("EMAIL_IN_USE", "Email address is already in use")
        const salt = crypto.randomBytes(16).toString('base64');
        const secret = pbkdf2Sync(request.password, salt, 1, 32, 'SHA512').toString('base64')
        const createdUser = {
            email: request.email,
            name: request.name,
            secret: secret,
            salt: salt
        }
        await this.userRepository.save(createdUser)
        return createdUser
    }

    generateToken = async (request: LoginRequest) => {
        const unauthorizedError = ServerError.unauthorized("INVALID_CREDENTIALS", "Username or password is incorrect")
        const existingUser = await this.userRepository.getByEmail(request.email)
        if (!existingUser) throw unauthorizedError
        const secret = pbkdf2Sync(request.password, existingUser.salt, 1, 32, 'SHA512').toString('base64')
        if (existingUser.secret !== secret) throw unauthorizedError
        // THIS IS A RANDOMLY GENERATED PRIVATE KEY, TO BE REPLACED WITH PROPER SECRET MANAGEMENT
        const privateKey =
            `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqIfOrQIAHKQu6
VaqmxcfUlFLN5mxQ9lrRxNsTr/NvcDfZY7Be+tNfbzTjekk87oLgOBSBnYY5fnGq
YVzjKCHAVsSjffhJe8PfMr6/j2LR4oS0sk62AR/6aEf5OJ6CyGDbA//RvHwl7eeO
oQo0nA1VtkFYTD0bsxv1IRZDDRZE3eIyHXuyHaI0Azq/hGzZ6WDwxpfe/X9rPYy5
Ule8HxUhgtg8xSwwEeMBgkk1IztxIDPDZv91wsgc4H1x9BNWaBZL7wRX9/9I72sa
41/jEEpHyaTMHE0cUfih+1qCKsvAGkqf0daQILZgxE2X1nVTjB2bltp3889zqtIF
pXBeqIlNAgMBAAECggEAN1oQ/yDX07mIuAP2PQi/ojpxrBNocqiXVoXlbC1aDjO3
xGlswjum2qZSGOBpbaIOp18iu/TnjXKfATKU8PAlMJFi2isXFppPt5YJ4gROTsPw
bz7DXIR+EKd0Mo+H6+/e9BBpO6bFq/rnVkEsxjzJa0TUBIG7pa+NscFhf7cZl2xw
p6D2ywY8LLm41WWHXMcAtoQK7VNPG2iLyGZGD7jwW9+6iKIYzxNJNsjUUioxendL
6AL9PmU7jSS3jvOzR1xNak5YJjlXxumy7qW2ABsQM/zYad8QAkT7raB/MPVubxus
WAXuF1511kH0+gDGRCz6Pgc1U2KgAiEof4t5Zc5smQKBgQD/UUnIgwuPPWVtgxZX
SazDIrmAh/b3dnsfdEI/MmkQ70YPeGe9YPTR1JwMFm4lUXyZwqkBsDe008UihvE0
8afldqXtxBCEz5k6ANhWO2otB+X4GcQUPF7eowVobRmNFmS2JntCKKh90bI2SVgl
L5Lr5LWUdlO4aefkSj8iLV3+KQKBgQDqwiq9Oc07kqjL8PGcEPfT/KhfkT94QHCJ
ZpYw+8SQOMMy3LeoEOB3CHlihgUf5OmbS3sIWBFZQvsQ96vxULYdlRHLoAcnEAy6
2tMVwKnQe9y2PTcGlhnjwQFws4kR4JNZhHUoSVbmOfC9c8PCDbiwyXTfvKsVYsI6
ey4cxKtOhQKBgA0x60lElIVbm/FT9ASg1x/inImq/TV+1xAiFwZjGZD5fLpx85KS
/zQU89egFSMymejsaYWf0NE0nJyTMsYUsyOlxR+LoXrrq7SWtJeITI11OgpfcoXF
NPX2oOHruYVUIfJT/MzHgyW1f6tUkQyi78nnMQcyMlN2jbh7qdWfWJs5AoGAVxdL
dcHQ0q348xfi+mwNFNbhu/qNmlYFqeOmCmwMoxh7yg26EJ6aN26sYZGoqwloZNVe
wlyxqvS/Ya8QWckAlv7riChJHwPERTnTH3nHRfH9kpopJMdguW6r0xy32CsBXy9V
q2lx1J1gI1ikIgSnJObH9gzvR1LJDZsPI1sO1mUCgYEA/EM64ipvuPpklwXW1O47
qFDutEDmMgk4t3iChzRN2xVVzxywqMiWto35sVQALx4t+bX0oZGj3JrK6plDDBP2
ZdmhnlUKCklCVtniH4XayRNs42LHFai27j1ula1FM8/OkHVA3ejewGcUh8/JOf+I
bhK9MoW7w8YFEYnZWaqIZQk=
-----END PRIVATE KEY-----
`
        const accessToken = jwt.sign({}, privateKey, {
            expiresIn: "1d",
            subject: existingUser.email,
            algorithm: "RS256"
        })

        return {
            "accessToken": accessToken,
        }
    }
}