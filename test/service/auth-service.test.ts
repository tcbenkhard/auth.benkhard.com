import {AuthService} from "../../src/service/auth-service";
import {UserRepository} from "../../src/repository/user-repository";
import {anything, instance, mock, verify, when} from "ts-mockito";
import {ServerError} from "@tcbenkhard/aws-utils";

describe('AuthService', () => {
    it('should raise when a username is already registered', async () => {
        const mockedRepository: UserRepository = mock(UserRepository);
        const repository = instance(mockedRepository)
        const service = new AuthService(repository)

        when(mockedRepository.getByEmail(anything())).thenResolve({
            email: 'test@test.com',
            name: 'Tester Test',
            secret: 'supersecretandencrypted',
            salt: 'complexsalt',
        });

        await expect(service.registerUser({
            password: '123',
            email: 'test@test.com',
            name: 'Tester Test'
        })).rejects.toThrow(ServerError)
    })

    it('should save the user when the emailaddress is not in use', async () => {
        const mockedRepository: UserRepository = mock(UserRepository);
        const repository = instance(mockedRepository)
        const service = new AuthService(repository)

        when(mockedRepository.getByEmail(anything())).thenResolve(undefined);

        await service.registerUser({
            password: '123',
            email: 'test@test.com',
            name: 'Tester Test'
        })
        verify(mockedRepository.save(anything())).called()})

    it('should return an access token when the credentials are correct', async () => {
        const mockedRepository: UserRepository = mock(UserRepository);
        const repository = instance(mockedRepository)
        const service = new AuthService(repository)

        when(mockedRepository.getByEmail(anything())).thenResolve({
            email: 'test@test.com',
            name: 'Tester Test',
            secret: 'KxjO2QvmdIeupjLwRk7kya5y/BuJOqswNa14v71oMiU=',
            salt: 'complexsalt',
        })

        const accessToken = await service.generateToken({
            email: 'test@test.com',
            password: '123'
        })

        expect(accessToken).toHaveProperty('accessToken')
        console.log(accessToken)
    })
})