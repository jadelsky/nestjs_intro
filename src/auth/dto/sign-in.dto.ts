import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SignInDto {
  @IsString()
  @ApiProperty({ example: 'john_doe' })
  @IsNotEmpty()
  username: string;

  @IsString()
  @ApiProperty({ example: 'strongPassword123' })
  @IsNotEmpty()
  password: string;
}