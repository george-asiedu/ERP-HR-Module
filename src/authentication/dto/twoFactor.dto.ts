import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString } from 'class-validator';

export class TwoFactorDto {
  @ApiProperty({example: 'george.asiedu@gmail.com', required: true})
  @IsEmail()
  @IsString()
  email!: string;

  @ApiProperty({example: 787643, required: true})
  @IsString()
  twoFactorCode!: string;
}