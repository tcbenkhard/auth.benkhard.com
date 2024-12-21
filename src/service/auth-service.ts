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
        if(!existingUser) throw unauthorizedError
        const secret = pbkdf2Sync(request.password, existingUser.salt, 1, 32, 'SHA512').toString('base64')
        if(existingUser.secret !== secret) throw unauthorizedError
        // THIS IS A RANDOMLY GENERATED PRIVATE KEY, TO BE REPLACED WITH PROPER SECRET MANAGEMENT
        const privateKey =
            `-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----`
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