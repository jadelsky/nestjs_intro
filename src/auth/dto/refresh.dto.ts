import { IsString, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshDto {
  @IsOptional()
  @IsString()
  @ApiProperty({
    example: '2fc5ae4a2f3a1fc348f3b267b28030d592b863f7e563d59ee98bdca733007026',
    required: false,
    description: 'Optional: refresh token; normally read from HttpOnly cookie',
  })
  refresh_token?: string;
}