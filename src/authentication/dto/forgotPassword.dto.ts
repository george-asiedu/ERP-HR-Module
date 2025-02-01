import { IsEmail, IsNotEmpty, IsString } from "class-validator";
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
  @ApiProperty({
    example: 'george.asiedu@gmail.com',
    required: true
  })
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email!: string;
}