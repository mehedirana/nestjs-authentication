// src/auth/dto/login.dto.ts
import { IsEmail, IsString, MinLength, MaxLength } from 'class-validator';
// import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  // @ApiProperty({ example: 'user@example.com' })
  @IsEmail()
  email: string;

  // @ApiProperty({ example: 'Password123!' })
  @IsString()
  @MinLength(6)
  @MaxLength(100)
  password: string;
}