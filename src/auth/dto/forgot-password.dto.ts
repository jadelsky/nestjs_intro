import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsOptional, IsString, ValidateIf } from 'class-validator';

export class ForgotPasswordDto {
  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'User email address (required if username is not provided)',
    required: false,
  })
  @ValidateIf((o) => !o.username)
  @IsEmail()
  email?: string;

  @ApiProperty({
    example: 'johnny123',
    description: 'Username (required if email is not provided)',
    required: false,
  })
  @ValidateIf((o) => !o.email)
  @IsString()
  username?: string;
}