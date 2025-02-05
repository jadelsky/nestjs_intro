import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { User } from '../users/users.entity';

@Module({
  imports: [
    // forwardRef(() => UsersModule),
    UsersModule,
    TypeOrmModule.forFeature([User])
  ],
  providers: [AuthService],
  controllers: [AuthController],
  exports: [AuthService],
})

export class AuthModule {}
