import { Body, Controller, Get, Post, HttpCode, HttpStatus, Query, UsePipes, ValidationPipe, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { ApiTags } from '@nestjs/swagger';
import { LoginUserSwagger, RegisterUserSwagger, RefreshTokenSwagger, VerifyEmailSwagger, ResendVerificationEmailSwagger, ForgotPasswordSwagger, ResetPasswordSwagger, DenyUsernameResetSwagger } from './../swagger.decorator';
import { UserCreateDto } from './../users/dto/userCreate.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { DenyUsernameResetDto } from './dto/deny-username-reset.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';

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
  signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto.username, signInDto.password);
  }

  @RegisterUserSwagger()
  @Post('register')
  async create(@Body() user: UserCreateDto): Promise<{ message: string }> {
    return this.authService.create(user);
  }

  @RefreshTokenSwagger()
  @Post('refresh')
  async refresh(@Body('refresh_token') refreshToken: string) {
    try {
      return await this.authService.refreshTokens(refreshToken);
    } catch (err) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
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
