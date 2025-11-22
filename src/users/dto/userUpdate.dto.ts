import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsOptional, MinLength } from 'class-validator';
import { UserRole } from '../users.entity';

export class UserUpdateDto {
  @IsOptional()
  @ApiProperty({ example: 'john_doe' })
  username?: string;

  @IsOptional()
  @MinLength(8)
  @ApiProperty({ example: 'strongPassword123' })
  password?: string;

  @IsOptional()
  @IsEmail({}, { message: 'Provided email has the wrong format' })
  @ApiProperty({ example: 'john@example.com' })
  email?: string;

  @IsOptional()
  @ApiProperty({ example: 'user' })
  role?: UserRole;
}