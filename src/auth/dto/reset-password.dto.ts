import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({ example: "jwt-token-here" })
  @IsString()
  token: string;

  @ApiProperty({ example: "NewSecurePassword123!" })
  @IsString()
  @MinLength(8)
  newPassword: string;

  @ApiProperty({ example: "NewSecurePassword123!" })
  @IsString()
  @MinLength(8)
  confirmPassword: string;
}