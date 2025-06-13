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

        const { accessTokenPayload, refreshTokenPayload } = this.buildTokenPayloads(user);
            
        const access_token = this.generateAccessToken(accessTokenPayload);
        const refreshToken = this.generateRefreshToken(refreshTokenPayload)
        return {access_token, refreshToken};
    }

    async refreshTokens(refreshToken: string): Promise<{ access_token: string; refresh_token: string }> {
        const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
    });

    const user = await this.usersService.findOneByUsername(payload.username);
        if (!user) {
            throw new UnauthorizedException('User not found');
        }

        const { accessTokenPayload, refreshTokenPayload } = this.buildTokenPayloads(user);

        return {
            access_token: this.generateAccessToken(accessTokenPayload),
            refresh_token: this.generateRefreshToken(refreshTokenPayload),
        };
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

    private buildTokenPayloads(user: User) {
        return {
        accessTokenPayload: {
            sub: user.id,
            username: user.username,
            role: user.role,
        },
        refreshTokenPayload: {
            sub: user.id,
            username: user.username,
        },
        };
    }
}
