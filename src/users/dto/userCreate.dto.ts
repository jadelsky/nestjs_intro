import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEnum, IsOptional } from 'class-validator';
import { IsEmail } from 'class-validator';
import { UserRole } from '../users.entity';

export class UserCreateDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: 'john_doe' })
  username: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: 'strongPassword123' })
  password: string;

  @IsEmail({}, { message: 'Provided email has the wrong format' })
  @IsNotEmpty()
  @ApiProperty({ example: 'john@example.com' })
  email: string;

  @IsEnum(UserRole)
  @IsOptional()
  @ApiProperty({ example: UserRole.USER, enum: UserRole, required: false })
  role?: UserRole;
}