import { IsEmail, IsEnum, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum UserRole {
  Admin = 'Admin',
  Employee = 'Employee'
}

export class CreateUserDto {
  @ApiProperty({
    example: 'George Asiedu',
    required: true
  })
  @IsString()
  @IsNotEmpty()
  name!: string;

  @ApiProperty({
    example: 'george.asiedu@gmail.com',
    required: true
  })
  @IsString()
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @ApiProperty({
    example: 'strongPass123',
    required: true
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password!: string;

  @ApiProperty({ example: "Employee", enum: UserRole })
  @IsEnum(UserRole)
  role!: UserRole;
}