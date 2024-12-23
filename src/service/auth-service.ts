import * as crypto from "node:crypto";
import {UserRepository} from "../repository/user-repository";
import {pbkdf2Sync} from "pbkdf2";
import {User} from "../model/user";
import {RegistrationRequest} from "../registration-handler";
import {getEnv, ServerError} from "@tcbenkhard/aws-utils";
import {LoginRequest} from "../login-handler";
import * as jwt from "jsonwebtoken";
import {DocumentClient} from "aws-sdk/clients/dynamodb";
import {SecretUtils} from "../util/secret";

export class AuthService {

    static build = () => {
        const dynamodb = new DocumentClient()
        const userRepository = new UserRepository(dynamodb)
        return new AuthService(userRepository)
    }

    constructor(private readonly userRepository: UserRepository) {
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
        const privateKey = await SecretUtils.getSecretValue(getEnv("JWT_PRIVATE_KEY_SECRET_ID"))
        const accessToken = jwt.sign({}, privateKey, {
            expiresIn: "1d",
            subject: existingUser.email,
            algorithm: "RS256"
        })

        return {
            "accessToken": accessToken,
        }
    }

    validateToken = async (token: string) => {
        const publicKey = await SecretUtils.getSecretValue(getEnv("JWT_PUBLIC_KEY_SECRET_ID"))
        try {
            jwt.verify(token, publicKey)
            console.info("Token is valid")
        } catch (e) {
            console.error(e)
            throw ServerError.unauthorized("INVALID_TOKEN", "Token is invalid")
        }
    }
}