import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class DenyUsernameResetDto {
  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1...',
    description: 'JWT token included in the deny-reset link sent to email'
  })
  @IsString()
  token: string;
}