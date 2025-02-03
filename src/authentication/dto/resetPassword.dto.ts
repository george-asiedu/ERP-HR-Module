import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
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