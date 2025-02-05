import { Body, Controller, Post, HttpCode, HttpStatus, UsePipes, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/sign-in.dto';
import { User } from './../users/users.entity';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @HttpCode(HttpStatus.OK)
    @Post('login')
    @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
    signIn(@Body() signInDto: SignInDto) {
      return this.authService.signIn(signInDto.username, signInDto.password);
    }

    @Post('register')
    async create(@Body() user: User): Promise<User> {
        return this.authService.create(user);
    }
}
