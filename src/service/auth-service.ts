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
            `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,EF0E4E1517E21C90

zmHltK+1cbRCcFc+FxY84Poalbao2svfUF8T5brROC1yHKKr/Ta2mrcer7A97JZg
Z1zmkGaABgkoXleUCS+rHZ4O80HOZZIcLcsKyYk+KSfIsa8+lDv3y49O3H2S8qUz
J1G8vP4w4O2xqM3X0rJgTql8qwLjwbmDwG2UtAPm1kTFXnWgZs9s6jcfggRAHK2P
fzFJg+DxItFclvAIn4tw3UV9EZFl5lVvikZg4P9HH9gg/eVB+2km5iKoYU+JL4fI
UXmxaa8b3ltwHqpSzDgSEBklDuq6VVExz65TwDGE3l/FclMT7nzGImREiodbhepm
i6fe/ycwuOWz6dUMCoJXMthRqXTz9jcGQONbFB9e06aslSMoUPsuayzHKXf5s3/L
8fzY36ReHrI2fBdu/lpsn99mlbE3vRN/U62wUVOqVuo/Bpff7p2/yp0ySwqFMdHX
m+5ZjbZ7X9jTYbbhXrr8w9pmHcWLGvRdEQWXyh/t1jhcre/PdE9Su6/qO2VQ4jwb
ouxSIad81s3PU7EKCoSxmqOKDK7VP3GF1rRlGfbRiim9WUOpSw7L1HrQhLO8nTYK
kvN9qnpxVqiluLP75XGOJvNv6uzVHG+FIU3yxAsoPPflOJBwR/fIgF6jbIR5svVA
ROBDmYz9PesH7ajT4uM0Cz76BIOJUC6dWi2rxe9fF9wij53us4fMOt706h28ibjT
JwS+o9N3Zu2EbdmpLcN8N43h2n1aTS/pNtjtEeA/UklkL4QYib0tFOZlGcg/2IqH
S5gEIizkeLVCK6hs3m1U4qQPNLuiZX5rxhs/FIYMrYi/5TiOLCjOck5BU4XyKyCY
7RIUN4w4SRtw41yauE885j6+XQHwZQXd2E29fWvipy3CXZDFPuJnpyGtFMnzlevw
ukcptDFMUMH8Xd2Nm/+rM6AXx0a682/hSnXJQxOGo5WhsoIshe6OwAm80n/qgM3P
tWlWm+YZebOqKNGk2+dGAuR/gSreoAz/FEFUK1x4f5r6OdhL7n/rRVGZgxaaThfH
0ImJg6QS8lRQ/QrO42MgK2z2Ue9pi7Knu+kmOfaK9MRstPdoV3UVZnPH/dMzrn9x
N0J+ii03c3KFDkXgKhUZRdIlhhVKnlavQq1I7PVDFzRzq3m74teXJaZZt0G7b5c8
m45duweXq3TxbVdVRnnT7IMxwaCs/i/sJWGM+AFqNyzRARuNaj/1pw1cgykzG/Em
O8alaRwVFL+Pg4YgG849Frqo5t3Et0a2rx3M2Uw4m8LtQwCfiU4VMWJVrFLRkT6m
BzwOSykCZCIhIRiHmH/uWzLfVtlCj3j1nfNA8gZgGUZqvADuY7E8MeMpd7irlASC
DcE2YgZkPwrIrqW34TNHk7MLMevcED0R34FCddOx1+FlkVD1ON6BHcz7Ro+dzpBf
WGH0nd23V7QzX7fG8OlHgllf/7CojbQRms3b9C86olnlLpKTZcPMLthYdJNf3/yd
LI6JpOOvYqqGoa+Hv1Dj5OJmomlOfHYTffL1VMwveCCfysQpQv5r0lYZbSH/CDZW
ugSxI3dqeY4bvEEeXuMbInHKDkF+BWqJcG2WuwJ66ngQ3xti2/6pIA==
-----END RSA PRIVATE KEY-----
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