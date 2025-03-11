import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { UserRole, User } from '../users/users.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserCreateDto } from './../users/dto/userCreate.dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(private readonly usersService: UsersService, 
                @InjectRepository(User)
                private usersRepository: Repository<User>,
                private jwtService: JwtService,
                private configService: ConfigService
    ) {}

    async signIn(username: string, pass: string): Promise<any> {
        const user = await this.usersService.findOneByUsername(username);
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }
        const isPassValid = await bcrypt.compare(pass, user.password);
        if (!isPassValid) {
            throw new UnauthorizedException('Invalid credentials');
        }
        // generate JWT token
        const payload = { username: user.username, sub: user.id };
        const access_token = this.generateAccessToken(payload);
        const refreshToken = this.generateRefreshToken(payload)
        return {access_token, refreshToken};
    }

    public generateAccessToken(payload: any) {
        return this.jwtService.sign(payload, {
          secret: this.configService.get<string>('JWT_SECRET'),
          expiresIn: `${this.configService.get<string>('JWT_EXPIRATION')}h`, // Short-lived access token
        });
      }

    public generateRefreshToken(payload: any) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            expiresIn: `${this.configService.get<string>('JWT_REFRESH_EXPIRATION')}d`
        });
    }


    async create(user: UserCreateDto): Promise<User> {
        const {username, email, password, role} = user;
        const existingUser = await this.usersRepository.findOne({
            where: [{ username: user.username }, { email: user.email }]
        });

        if (existingUser) {
            throw new BadRequestException(
                `User with ${existingUser.username === username ? 'this username' : 'this email'} already exists.`
            );
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = this.usersRepository.create({
            username,
            email,
            password: hashedPassword,
            role: role || UserRole.USER
        });

        return await this.usersRepository.save(newUser);
    }
}
