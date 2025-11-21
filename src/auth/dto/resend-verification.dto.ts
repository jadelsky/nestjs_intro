import { ApiProperty } from '@nestjs/swagger';
import { IsEmail } from 'class-validator';

export class ResendVerificationDto {
    @ApiProperty({
        example: 'user@example.com',
        description: 'Email address of the user requesting a new verification link',
    })
    @IsEmail()
    email: string;
}