import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class VerificationCodeDto {
  @ApiProperty({ example: 'george.asiedu@gmail.com', required: true })
  @IsString()
  @IsNotEmpty()
  @IsEmail()
  email!: string;

  @ApiProperty({example: 787643, required: true})
  @IsString()
  @IsNotEmpty()
  verificationCode!: string;
}