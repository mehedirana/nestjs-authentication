// src/users/dto/update-user.dto.ts
import { PartialType } from '@nestjs/swagger';
import { CreateUserDto } from './create-user.dto';
import { IsOptional, IsString, IsEmail, MinLength, MaxLength } from 'class-validator';

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @IsEmail()
  @IsOptional()
  email?: string;

  @IsString()
  @MinLength(3)
  @MaxLength(30)
  @IsOptional()
  username?: string;

  @IsString()
  @IsOptional()
  firstName?: string;

  @IsString()
  @IsOptional()
  lastName?: string;
}