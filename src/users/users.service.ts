// src/users/users.service.ts
import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Not } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { v4 as uuidv4 } from 'uuid';

import { User, UserStatus } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private configService: ConfigService,
  ) {}

  // Create new user
  async create(createUserDto: CreateUserDto): Promise<User> {
    // Check if email exists
    const emailExists = await this.findByEmail(createUserDto.email);
    if (emailExists) {
      throw new ConflictException('Email already exists');
    }

    // Check if username exists
    const usernameExists = await this.findByUsername(createUserDto.username);
    if (usernameExists) {
      throw new ConflictException('Username already exists');
    }

    // Create verification token
    const verificationToken = uuidv4();
    const verificationTokenExpires = new Date();
    verificationTokenExpires.setHours(
      verificationTokenExpires.getHours() + 24,
    ); // 24 hours

    try {
      const user = this.usersRepository.create({
        ...createUserDto,
        verificationToken,
        verificationTokenExpires,
        status: UserStatus.PENDING,
      });

      return await this.usersRepository.save(user);
    } catch (error) {
      if (error.code === '23505') {
        throw new ConflictException('User already exists');
      }
      throw new InternalServerErrorException('Failed to create user');
    }
  }

  // Find all users with pagination
  async findAll(
    page = 1,
    limit = 10,
    search?: string,
  ): Promise<{ data: User[]; total: number; page: number; limit: number }> {
    const skip = (page - 1) * limit;
    const query = this.usersRepository.createQueryBuilder('user');

    if (search) {
      query.where(
        '(user.email LIKE :search OR user.username LIKE :search OR user.firstName LIKE :search OR user.lastName LIKE :search)',
        { search: `%${search}%` },
      );
    }

    query.orderBy('user.createdAt', 'DESC');
    query.skip(skip).take(limit);

    const [data, total] = await query.getManyAndCount();

    return {
      data,
      total,
      page,
      limit,
    };
  }

  // Find user by ID
  async findOne(id: string): Promise<User> {
    const user = await this.usersRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  // Find user by email
  async findByEmail(email: string): Promise<User> {
    return this.usersRepository.findOne({ where: { email } });
  }

  // Find user by username
  async findByUsername(username: string): Promise<User> {
    return this.usersRepository.findOne({ where: { username } });
  }

  // Update user
  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.findOne(id);

    // Check if new email is unique
    if (updateUserDto.email && updateUserDto.email !== user.email) {
      const emailExists = await this.usersRepository.findOne({
        where: { email: updateUserDto.email, id: Not(id) },
      });
      if (emailExists) {
        throw new ConflictException('Email already exists');
      }
    }

    // Check if new username is unique
    if (updateUserDto.username && updateUserDto.username !== user.username) {
      const usernameExists = await this.usersRepository.findOne({
        where: { username: updateUserDto.username, id: Not(id) },
      });
      if (usernameExists) {
        throw new ConflictException('Username already exists');
      }
    }

    Object.assign(user, updateUserDto);
    return await this.usersRepository.save(user);
  }

  // Delete user (soft delete)
  async remove(id: string): Promise<void> {
    const user = await this.findOne(id);
    user.status = UserStatus.INACTIVE;
    await this.usersRepository.save(user);
  }

  // Change password
  async changePassword(id: string, changePasswordDto: ChangePasswordDto): Promise<void> {
    const user = await this.findOne(id);

    // Verify current password
    const isValid = await user.validatePassword(changePasswordDto.currentPassword);
    if (!isValid) {
      throw new BadRequestException('Current password is incorrect');
    }

    // Update password
    user.password = changePasswordDto.newPassword;
    await this.usersRepository.save(user);
  }

  // Verify email
  async verifyEmail(token: string): Promise<User> {
    const user = await this.usersRepository.findOne({
      where: { verificationToken: token },
    });

    if (!user) {
      throw new NotFoundException('Invalid verification token');
    }

    if (user.verificationTokenExpires < new Date()) {
      throw new BadRequestException('Verification token has expired');
    }

    user.emailVerified = true;
    user.verificationToken = null;
    user.verificationTokenExpires = null;
    user.status = UserStatus.ACTIVE;

    return await this.usersRepository.save(user);
  }

  // Create password reset token
  async createPasswordResetToken(email: string): Promise<string> {
    const user = await this.findByEmail(email);
    if (!user) {
      // Don't reveal that user doesn't exist
      return null;
    }

    const resetToken = uuidv4();
    const resetTokenExpires = new Date();
    resetTokenExpires.setHours(resetTokenExpires.getHours() + 1); // 1 hour

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpires;

    await this.usersRepository.save(user);
    return resetToken;
  }

  // Reset password with token
  async resetPassword(token: string, newPassword: string): Promise<void> {
    const user = await this.usersRepository.findOne({
      where: { resetPasswordToken: token },
    });

    if (!user) {
      throw new NotFoundException('Invalid reset token');
    }

    if (user.resetPasswordExpires < new Date()) {
      throw new BadRequestException('Reset token has expired');
    }

    user.password = newPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    user.resetLoginAttempts();

    await this.usersRepository.save(user);
  }

  // Update last login
  async updateLastLogin(id: string): Promise<void> {
    await this.usersRepository.update(id, {
      lastLogin: new Date(),
      loginAttempts: 0,
      lockUntil: null,
    });
  }

  // Increment login attempts
  async incrementLoginAttempts(email: string): Promise<void> {
    const user = await this.findByEmail(email);
    if (user) {
      user.incrementLoginAttempts();
      await this.usersRepository.save(user);
    }
  }
}