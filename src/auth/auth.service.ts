import { BadRequestException, Injectable, UnauthorizedException, ForbiddenException, NotFoundException } from '@nestjs/common';
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
import { EmailService } from './email.service';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';

@Injectable()
export class AuthService {
    constructor(private readonly usersService: UsersService,
        @InjectRepository(User)
        private usersRepository: Repository<User>,
        private jwtService: JwtService,
        private configService: ConfigService,
        @InjectRepository(RefreshToken)
        private refreshTokenRepository: Repository<RefreshToken>,
        private readonly emailService: EmailService,
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

        if (user.role !== UserRole.ADMIN && !user.emailVerified) {
            throw new ForbiddenException({
                message: 'Email not verified. Please verify your email before logging in.',
                canResend: true,
            });
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

    public generateEmailVerificationToken(payload: any) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('EMAIL_VERIFICATION_SECRET'),
            expiresIn: `${this.configService.get<string>('EMAIL_VERIFICATION_EXPIRATION')}d`
        });
    }

    public generatePasswordResetToken(payload: any) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('PASSWORD_RESET_SECRET'),
            expiresIn: `${this.configService.get<string>('PASSWORD_RESET_EXPIRATION')}h`
        });
    }

        public generateDenyUsernameResetToken(payload: any) {
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('PASSWORD_RESET_DENY_SECRET'),
            expiresIn: `${this.configService.get<string>('PASSWORD_RESET_DENY_EXPIRATION')}h`
        });
    }

    async create(user: UserCreateDto): Promise<{ message: string }> {
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
            role: UserRole.USER,
            emailVerified: false
        });

        const savedUser = await this.usersRepository.save(newUser);

        const { emailVerificationPayload } = this.buildTokenPayloads(savedUser);

        const emailVerificationToken = this.generateEmailVerificationToken(emailVerificationPayload);

        // Build verification link
        const verifyUrl = `${process.env.BACKEND_URL}/auth/verify-email?token=${encodeURIComponent(emailVerificationToken)}`;

        // Send verification email
        await this.emailService.sendVerificationEmail(savedUser.email, verifyUrl);

        return {
            message: 'Registration successful. Please check your email to verify your account.',
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
            emailVerificationPayload: {
                sub: user.id
            },
            passwordResetPayload: {
                sub: user.id
            },
        };
    }

    async verifyEmailToken(token: string): Promise<any> {
        try {
            const payload = this.jwtService.verify(token, {
                secret: this.configService.get<string>('EMAIL_VERIFICATION_SECRET'),
            });
            const userId = payload.sub;

            const user = await this.usersRepository.findOne({ where: { id: userId } });

            if (!user) {
                throw new NotFoundException('User not found');
            }

            if (user.emailVerified) {
                return 'Email already verified';
            }

            user.emailVerified = true;
            await this.usersRepository.save(user);

            const updatedUser = await this.usersRepository.findOne({ where: { id: userId } });
            if (!updatedUser) {
                throw new NotFoundException('User not found after update');
            }

            return 'Email verified successfully';
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return {
                    message: 'Verification token expired',
                    canResend: true,
                };
            }

            throw new BadRequestException({
                message: 'Unable to verify token',
                canResend: false,
            });
        }
    }

    async resendVerificationEmail(email: string) {
        const user = await this.usersRepository.findOne({ where: { email } });

        // If user exists and is not verified, send verification email
        if (user && !user.emailVerified) {
            const { emailVerificationPayload } = this.buildTokenPayloads(user);
            const newToken = this.generateEmailVerificationToken(emailVerificationPayload);

            const verifyUrl = `${this.configService.get('BACKEND_URL')}/auth/verify-email?token=${newToken}`;

            await this.emailService.sendVerificationEmail(user.email, verifyUrl);
        }

        return { message: 'If an account with this email exists, a verification email has been sent.' };
    }

    async forgotPassword(dto: ForgotPasswordDto) {
        const { email, username } = dto;

        const identifier = email ?? username;

        // Always prepare generic response to avoid user enumeration
        const genericResponse = {
            message: 'If an account exists, a password reset email has been sent.',
        };

        const user = await this.usersRepository.findOne({
            where: [{ email: identifier }, { username: identifier }],
        });

        if (!user) return genericResponse;

        if (!user.emailVerified) return genericResponse;

        const identifierIsUsername = identifier === user.username;

        if (identifierIsUsername && user.allowUsernameReset === false) {
            return genericResponse;
        }

        // Generate secure JWT reset token
        const { passwordResetPayload } = this.buildTokenPayloads(user);
        const resetToken = this.generatePasswordResetToken(passwordResetPayload);
        const resetUrl = `${this.configService.get<string>('BACKEND_URL')}/auth/reset-password?token=${resetToken}`;

        let denyUrl: string | undefined;

        // Generate deny-username-reset token and URL if identifier is username
        if (identifierIsUsername) {
            const denyToken = this.generateDenyUsernameResetToken({ sub: user.id });
            denyUrl = `${this.configService.get<string>('BACKEND_URL')}/auth/deny-username-reset?token=${denyToken}`;
        }

        // Send password reset email with resetUrl and optional denyUrl
        await this.emailService.sendPasswordResetEmail(user.email, resetUrl, denyUrl);

        // If reset was initiated using username → return masked email for UX
        if (identifierIsUsername) {
            return {
                message: genericResponse.message,
                maskedEmail: this.emailService.maskEmail(user.email),
            };
        }

        // Otherwise (email used) → return generic response only
        return genericResponse;
    }

    async denyUsernameReset(token: string) {
        try {
            const payload = this.jwtService.verify(token, {
                secret: this.configService.get<string>('PASSWORD_RESET_DENY_SECRET'),
            });

            const user = await this.usersRepository.findOne({
                where: { id: payload.sub },
            });

            if (!user) throw new NotFoundException();

            user.allowUsernameReset = false;
            await this.usersRepository.save(user);

            return { message: 'Username-based password reset disabled.' };
        } catch (err) {
            throw new BadRequestException('Invalid or expired token');
        }
    }

    async resetPassword(dto: ResetPasswordDto) {
        const { token, newPassword, confirmPassword } = dto;

        if (newPassword !== confirmPassword) {
            throw new BadRequestException('Passwords do not match');
        }

        let payload;
        try {
            payload = this.jwtService.verify(token, {
                secret: this.configService.get<string>('PASSWORD_RESET_SECRET'),
            });
        } catch (e) {
            throw new BadRequestException('Invalid or expired token');
        }

        const user = await this.usersRepository.findOne({
            where: { id: payload.sub },
        });

        if (!user) throw new NotFoundException('User not found');

        user.password = await bcrypt.hash(newPassword, 10);
        await this.usersRepository.save(user);

        return { message: 'Password updated successfully' };
    }
}
