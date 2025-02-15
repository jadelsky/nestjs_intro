import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsOptional } from 'class-validator';

export class UserUpdateDto {
  @IsOptional()
  @ApiProperty({ example: 'john_doe' })
  username?: string;

  @IsOptional()
  @ApiProperty({ example: 'strongPassword123' })
  password?: string;

  @IsOptional()
  @IsEmail({}, { message: 'Provided email has the wrong format' })
  @ApiProperty({ example: 'john@example.com' })
  email?: string;
}