import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class TwoFactorDto {
  @ApiProperty({example: '787643', required: true})
  @IsString()
  twoFactorCode!: string;
}