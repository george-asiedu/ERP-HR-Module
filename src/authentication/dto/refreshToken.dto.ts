import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshTokenDto{
  @ApiProperty({example: '6a7b8c9d.e10f11g12h', required: true})
  @IsString()
  @IsNotEmpty()
  refreshToken!: string;
}