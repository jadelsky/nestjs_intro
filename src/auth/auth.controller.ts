import { Body, Controller, Get, Post, HttpCode, HttpStatus, Query, UsePipes, ValidationPipe, UnauthorizedException, Res, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshDto } from './dto/refresh.dto';
import { ApiTags } from '@nestjs/swagger';
import { LoginUserSwagger, RegisterUserSwagger, RefreshTokenSwagger, VerifyEmailSwagger, ResendVerificationEmailSwagger, ForgotPasswordSwagger, ResetPasswordSwagger, DenyUsernameResetSwagger } from './../swagger.decorator';
import { UserCreateDto } from './../users/dto/userCreate.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { DenyUsernameResetDto } from './dto/deny-username-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Request, Response } from 'express';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private userService: UsersService
  ) { }

  @LoginUserSwagger()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  async signIn(@Body() signInDto: SignInDto, @Res({ passthrough: true }) res: Response) {
    const { accessToken, refreshToken } = await this.authService.signIn(
      signInDto.username,
      signInDto.password,
      undefined,
      signInDto.rememberMe,
    );

    const rememberMe = signInDto.rememberMe ?? false;
    const baseExpirationDays = Number(this.configService.get<number>('REFRESH_EXPIRATION')) || 7;
    const expirationDays = rememberMe ? 90 : baseExpirationDays;
    const isProd = this.configService.get<string>('NODE_ENV') === 'production';

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'strict',
      path: '/',
      maxAge: expirationDays * 24 * 60 * 60 * 1000,
    });

    return { accessToken };
  }

  @RegisterUserSwagger()
  @Post('register')
  async create(@Body() user: UserCreateDto): Promise<{ message: string }> {
    return this.authService.create(user);
  }

  @RefreshTokenSwagger()
  @Post('refresh')
  async refresh(@Req() req: Request, @Body() dto: RefreshDto, @Res({ passthrough: true }) res: Response) {
    const cookieHeader = req.headers.cookie ?? '';
    const cookieToken = cookieHeader
      .split(';')
      .map((c) => c.trim())
      .find((c) => c.startsWith('refresh_token='))
      ?.split('=')[1];

    const refreshToken = dto?.refresh_token ?? cookieToken;

    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    try {
      const { accessToken, refreshToken: newRefreshToken, rememberMe } = await this.authService.refreshTokens(refreshToken);

      const baseExpirationDays = Number(this.configService.get<number>('REFRESH_EXPIRATION')) || 7;
      const expirationDays = rememberMe ? 90 : baseExpirationDays;
      const isProd = this.configService.get<string>('NODE_ENV') === 'production';

      res.cookie('refresh_token', newRefreshToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        path: '/',
        maxAge: expirationDays * 24 * 60 * 60 * 1000,
      });

      return { accessToken };
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Req() req: Request, @Body() dto: RefreshDto, @Res({ passthrough: true }) res: Response): Promise<void> {
    const cookieHeader = req.headers.cookie ?? '';
    const cookieToken = cookieHeader
      .split(';')
      .map((c) => c.trim())
      .find((c) => c.startsWith('refresh_token='))
      ?.split('=')[1];

    const refreshToken = dto?.refresh_token ?? cookieToken;

    if (refreshToken) {
      await this.authService.logout(refreshToken);
    }

    res.clearCookie('refresh_token', {
      path: '/',
      sameSite: 'strict',
    });
  }

  @VerifyEmailSwagger()
  @Get('verify-email')
  async verifyEmail(@Query('token') token: string): Promise<{ message: string }> {
    token = decodeURIComponent(token);
    const message = await this.authService.verifyEmailToken(token);
    return { message };
  }

  @ResendVerificationEmailSwagger()
  @Post('resend-verification')
  async resendVerification(@Body('email') email: string) {
    return this.authService.resendVerificationEmail(email);
  }
  
  @Post('forgot-password')
  @ForgotPasswordSwagger()
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.authService.forgotPassword(dto);
  }

  @Post('deny-username-reset')
  @DenyUsernameResetSwagger()
  async denyUsernameReset(@Body() dto: DenyUsernameResetDto) {
    return this.authService.denyUsernameReset(dto.token);
  }

  @Post('reset-password')
  @ResetPasswordSwagger()
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.authService.resetPassword(dto);
  }
}
