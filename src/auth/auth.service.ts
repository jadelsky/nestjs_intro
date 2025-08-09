import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { UserRole, User } from '../users/users.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserCreateDto } from './../users/dto/userCreate.dto';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RefreshToken } from './entities/refresh-token.entity';
import { UserRegisterDto } from 'src/users/dto/userRegister.dto';

@Injectable()
export class AuthService {
    constructor(private readonly usersService: UsersService,
        @InjectRepository(User)
        private usersRepository: Repository<User>,
        private jwtService: JwtService,
        private configService: ConfigService,
        @InjectRepository(RefreshToken) 
        private refreshTokenRepository: Repository<RefreshToken>
    ) { }

    async signIn(username: string, pass: string, deviceInfo?: string): Promise<any> {
        const user = await this.usersService.findOneByUsername(username);
        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }
        const isPassValid = await bcrypt.compare(pass, user.password);
        if (!isPassValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const { accessTokenPayload } = this.buildTokenPayloads(user);

        const access_token = this.generateAccessToken(accessTokenPayload);
        const refreshToken = await this.generateOpaqueRefreshToken(user.id, deviceInfo);
        return { access_token, refreshToken };
    }

    private async generateOpaqueRefreshToken(userId: number, deviceInfo?: string): Promise<string> {
        // Generate a cryptographically secure random token
        const token = crypto.randomBytes(32).toString('hex');

        // Calculate expiration date
        const expirationDays = Number(this.configService.get<number>('REFRESH_EXPIRATION')) || 7;
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + expirationDays);

        // Optional: Revoke existing refresh tokens for this user (single session)
        // await this.revokeAllUserRefreshTokens(userId);

        // Save to database
        const refreshTokenEntity = this.refreshTokenRepository.create({
            token,
            userId,
            expiresAt,
            deviceInfo,
            isRevoked: false,
        });

        await this.refreshTokenRepository.save(refreshTokenEntity);
        return token;
    }

    async refreshTokens(refreshToken: string): Promise<any> {
        const tokenEntity = await this.refreshTokenRepository.findOne({
            where: { token: refreshToken, isRevoked: false },
            relations: ['user'],
        });

        if (!tokenEntity) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        if (tokenEntity.expiresAt < new Date()) {
            // Clean up expired token
            await this.refreshTokenRepository.remove(tokenEntity);
            throw new UnauthorizedException('Refresh token expired');
        }

        const user = tokenEntity.user;
        const { accessTokenPayload } = this.buildTokenPayloads(user);

        const access_token = this.generateAccessToken(accessTokenPayload);

        // Generate new refresh token and revoke the old one
        const newRefreshToken = await this.generateOpaqueRefreshToken(user.id, tokenEntity.deviceInfo);
        await this.revokeRefreshToken(refreshToken); // Revoke old token
        
        return { access_token, refreshToken: newRefreshToken };
    }

    async revokeRefreshToken(refreshToken: string): Promise<void> {
        const tokenEntity = await this.refreshTokenRepository.findOne({
            where: { token: refreshToken },
        });

        if (tokenEntity) {
            tokenEntity.isRevoked = true;
            await this.refreshTokenRepository.save(tokenEntity);
        }
    }

    async revokeAllUserRefreshTokens(userId: number): Promise<void> {
        await this.refreshTokenRepository.update(
            { userId, isRevoked: false },
            { isRevoked: true }
        );
    }

    async logout(refreshToken: string): Promise<void> {
        await this.revokeRefreshToken(refreshToken);
    }

    // Clean up expired tokens (run this periodically with a cron job)
    async cleanupExpiredTokens(): Promise<void> {
        await this.refreshTokenRepository.delete({
            expiresAt: { $lt: new Date() } as any,
        });
    }

    public generateAccessToken(payload: any) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_SECRET'),
            expiresIn: `${this.configService.get<string>('JWT_EXPIRATION')}h`, // Short-lived access token
        });
    }

    public generateRefreshToken(payload: any) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('REFRESH_SECRET'),
            expiresIn: `${this.configService.get<string>('REFRESH_EXPIRATION')}d`
        });
    }


    async create(user: UserCreateDto): Promise<UserRegisterDto> {
        const { username, email, password } = user;
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
            role: UserRole.USER
        });

        const savedUser = await this.usersRepository.save(newUser);

        return {
            username: savedUser.username,
            email: savedUser.email,
        };
    }

    private buildTokenPayloads(user: User) {
        return {
            accessTokenPayload: {
                sub: user.id,
                username: user.username,
                role: user.role,
                publicId: user.publicId,
            },
            refreshTokenPayload: {
                sub: user.id,
                username: user.username,
            },
        };
    }
}
