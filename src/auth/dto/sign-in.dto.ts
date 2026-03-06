import { IsString, IsNotEmpty, IsOptional, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';

export class SignInDto {
  @IsString()
  @ApiProperty({ example: 'john_doe' })
  @IsNotEmpty()
  username: string;

  @IsString()
  @ApiProperty({ example: 'strongPassword123' })
  @IsNotEmpty()
  password: string;

  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => value === true || value === 'true')
  @ApiProperty({ example: false, required: false, description: 'When true, refresh token lives 90 days' })
  rememberMe?: boolean;
}