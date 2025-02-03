import { ApiProperty } from "@nestjs/swagger";
import { IsNotEmpty, IsString } from "class-validator";

export class VerificationCodeDto {
  @ApiProperty({example: '787643', required: true})
  @IsString()
  @IsNotEmpty()
  verificationCode!: string;
}