import { Body, Controller, Post, HttpCode, HttpStatus, UsePipes, ValidationPipe, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { User } from './../users/users.entity';
import { ApiTags } from '@nestjs/swagger';
import { LoginUserSwagger, RegisterUserSwagger, RefreshTokenSwagger } from './../swagger.decorator';
import { UserCreateDto } from './../users/dto/userCreate.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService,
      private jwtService: JwtService,
      private configService: ConfigService
    ) {}

    @LoginUserSwagger()
    @HttpCode(HttpStatus.OK)
    @Post('login')
    @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
    signIn(@Body() signInDto: SignInDto) {
      return this.authService.signIn(signInDto.username, signInDto.password);
    }

    @RegisterUserSwagger()
    @Post('register')
    async create(@Body() user: UserCreateDto): Promise<User> {
        return this.authService.create(user);
    }

    @RefreshTokenSwagger()
    @Post('refresh')
    async refresh(@Body('refresh_token') refreshToken: string) {
      try {
        const payload = this.jwtService.verify(refreshToken, {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        });
  
        return {
          access_token: this.authService.generateAccessToken({
            sub: payload.sub,
            username: payload.username,
          }),
        };
      } catch (err) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }
    }
}
