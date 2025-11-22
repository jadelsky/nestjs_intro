import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsEnum, IsOptional, MinLength } from 'class-validator';
import { IsEmail } from 'class-validator';

export class UserCreateDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: 'john_doe' })
  username: string;

  @IsString()
  @MinLength(8)
  @ApiProperty({ example: 'strongPassword123' })
  password: string;

  @IsEmail({}, { message: 'Provided email has the wrong format' })
  @IsNotEmpty()
  @ApiProperty({ example: 'john@example.com' })
  email: string;
}