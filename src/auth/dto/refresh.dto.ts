import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshDto {
  @IsString()
  @ApiProperty({ example: '2fc5ae4a2f3a1fc348f3b267b28030d592b863f7e563d59ee98bdca733007026' })
  @IsNotEmpty()
  refresh_token: string;
}