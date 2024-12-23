import * as crypto from "node:crypto";
import {UserRepository} from "../repository/user-repository";
import {pbkdf2Sync} from "pbkdf2";
import {User} from "../model/user";
import {RegistrationRequest} from "../registration-handler";
import {ServerError} from "@tcbenkhard/aws-utils";
import {LoginRequest} from "../login-handler";
import * as jwt from "jsonwebtoken";

export class AuthService {

    constructor(private readonly userRepository: UserRepository, private readonly privateKey: string, private readonly publicKey: string) {
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

        const accessToken = jwt.sign({}, this.privateKey, {
            expiresIn: "1d",
            subject: existingUser.email,
            algorithm: "RS256"
        })

        return {
            "accessToken": accessToken,
        }
    }

    validateToken = async (token: string) => {
        try {
            jwt.verify(token, this.publicKey)
        } catch (e) {
            console.error(e)
            throw ServerError.unauthorized("INVALID_TOKEN", "Token is invalid")
        }
    }
}