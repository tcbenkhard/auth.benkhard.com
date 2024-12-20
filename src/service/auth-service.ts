import * as crypto from "node:crypto";
import {UserRepository} from "../repository/user-repository";
import {pbkdf2Sync} from "pbkdf2";
import {User} from "../model/user";
import {RegistrationRequest} from "../registration-handler";
import {ServerError} from "@tcbenkhard/aws-utils";

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
}