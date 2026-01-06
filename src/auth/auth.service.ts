// src/auth/auth.service.ts
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';

import { UsersService } from '../users/users.service';
import { User, UserStatus } from '../users/entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailerService: MailerService,
  ) {}

  // Validate user credentials
  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      return null;
    }

    // Check if account is locked
    if (user.isLocked()) {
      throw new UnauthorizedException('Account is temporarily locked. Try again later.');
    }

    // Check password
    const isPasswordValid = await user.validatePassword(password);
    
    if (!isPasswordValid) {
      // Increment login attempts
      await this.usersService.incrementLoginAttempts(email);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Reset login attempts on successful login
    user.resetLoginAttempts();
    await this.usersService.updateLastLogin(user.id);

    return user;
  }

  // Login
  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.email, loginDto.password);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException('Account is not active');
    }

    const tokens = await this.generateTokens(user);
    
    return {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
      ...tokens,
    };
  }

  // Register new user
  async register(registerDto: RegisterDto) {
    const user = await this.usersService.create(registerDto);

    // Send verification email
    await this.sendVerificationEmail(user);

    const tokens = await this.generateTokens(user);

    return {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
      ...tokens,
      message: 'Registration successful. Please check your email to verify your account.',
    };
  }

  // Generate access and refresh tokens
  async generateTokens(user: User) {
    const payload = {
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('jwt.secret'),
        expiresIn: this.configService.get('jwt.expiresIn'),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('jwt.refreshSecret'),
        expiresIn: this.configService.get('jwt.refreshExpiresIn'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresIn: this.configService.get('jwt.expiresIn'),
    };
  }

  // Refresh token
  async refreshToken(refreshToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('jwt.refreshSecret'),
      });

      const user = await this.usersService.findOne(payload.sub);
      
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      return this.generateTokens(user);
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  // Send verification email
  async sendVerificationEmail(user: User): Promise<void> {
    try {
      const verificationUrl = `${this.configService.get('frontendUrl')}/verify-email?token=${user.verificationToken}`;

      await this.mailerService.sendMail({
        to: user.email,
        subject: 'Verify Your Email Address',
        template: 'verify-email',
        context: {
          name: user.fullName || user.username,
          verificationUrl,
          supportEmail: this.configService.get('mail.from'),
        },
      });
    } catch (error) {
      console.error('Failed to send verification email:', error);
      // Don't throw error - we don't want registration to fail if email fails
    }
  }

  // Send password reset email
  async sendPasswordResetEmail(email: string): Promise<void> {
    const resetToken = await this.usersService.createPasswordResetToken(email);
    
    if (!resetToken) {
      // Don't reveal that user doesn't exist
      return;
    }

    try {
      const resetUrl = `${this.configService.get('frontendUrl')}/reset-password?token=${resetToken}`;

      await this.mailerService.sendMail({
        to: email,
        subject: 'Reset Your Password',
        template: 'reset-password',
        context: {
          resetUrl,
          expiresIn: '1 hour',
          supportEmail: this.configService.get('mail.from'),
        },
      });
    } catch (error) {
      console.error('Failed to send password reset email:', error);
      throw new InternalServerErrorException('Failed to send password reset email');
    }
  }

  // Verify email
  async verifyEmail(token: string): Promise<{ message: string }> {
    const user = await this.usersService.verifyEmail(token);
    
    return {
      message: 'Email verified successfully. Your account is now active.',
    };
  }

  // Forgot password
  async forgotPassword(email: string): Promise<{ message: string }> {
    await this.sendPasswordResetEmail(email);
    
    return {
      message: 'If an account exists with this email, you will receive a password reset link.',
    };
  }

  // Reset password
  async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
    await this.usersService.resetPassword(token, newPassword);
    
    return {
      message: 'Password reset successfully. You can now login with your new password.',
    };
  }

  // Logout (client-side - we just return success)
  async logout(): Promise<{ message: string }> {
    return {
      message: 'Logged out successfully',
    };
  }
}