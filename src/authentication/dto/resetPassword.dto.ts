import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({ example: 'george.asiedu@gmail.com', required: true })
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email!: string;

  @ApiProperty({ example: 'strongPass123', required: true })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  newPassword!: string;

  @ApiProperty({ example: 'strongPass123', required: true })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  confirmNewPassword!: string;
}