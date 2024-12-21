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
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
            QyNTUxOQAAACAVXRfyCDioEO05FgpvtWIyD4xbiI5XxAvcpeoXDGnbJgAAAJitAisPrQIr
            DwAAAAtzc2gtZWQyNTUxOQAAACAVXRfyCDioEO05FgpvtWIyD4xbiI5XxAvcpeoXDGnbJg
            AAAECSjeVLDK5jW9M91DR23lEpJrDkm93hgdskBuoE8HVsMRVdF/IIOKgQ7TkWCm+1YjIP
            jFuIjlfEC9yl6hcMadsmAAAAFXRjYmVuQERFU0tUT1AtMFIwU1BMVA==
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