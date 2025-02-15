import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { User } from '../users/users.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserCreateDto } from './../users/dto/userCreate.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
    constructor(private readonly usersService: UsersService, 
                @InjectRepository(User)
                private usersRepository: Repository<User>,
    ) {}

    async signIn(username: string, pass: string): Promise<any> {
        const user = await this.usersService.findOneByUsername(username);
        if (user?.password !== pass) {
            throw new UnauthorizedException('Invalid credentials');
        }
        const { password, ...result } = user;
        // TODO: Generate a JWT and return it here
        // instead of the user object
        return result;
    }

    async create(user: UserCreateDto): Promise<User> {
        const {username, email, password} = user;
        const existingUser = await this.usersRepository.findOne({
            where: [{ username }, { email }]
        });

        if (existingUser) {
            if (existingUser.username === username) {
                throw new BadRequestException('Username already exists');
            }
            if (existingUser.email === email) {
                throw new BadRequestException('Email already exists');
            }
        }

        // Hash password
        // const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = this.usersRepository.create({
            username,
            email,
            password
        });

        return this.usersRepository.save(newUser);
    }
}
