// src/users/entities/user.entity.ts
import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
    BeforeInsert,
    BeforeUpdate,
    OneToMany,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import * as bcrypt from 'bcrypt';

export enum UserRole {
    USER = 'user',
    ADMIN = 'admin',
    MODERATOR = 'moderator',
}

export enum UserStatus {
    PENDING = 'pending',
    ACTIVE = 'active',
    INACTIVE = 'inactive',
    BANNED = 'banned',
}

@Entity('users')
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ unique: true })
    email: string;

    @Column({ unique: true, nullable: true })
    username: string;

    @Column()
    @Exclude()
    password: string;

    @Column({ name: 'first_name', nullable: true })
    firstName: string;

    @Column({ name: 'last_name', nullable: true })
    lastName: string;

    @Column({
        type: 'enum',
        enum: UserRole,
        default: UserRole.USER,
    })
    role: UserRole;

    @Column({
        type: 'enum',
        enum: UserStatus,
        default: UserStatus.PENDING,
    })
    status: UserStatus;

    @Column({ name: 'email_verified', default: false })
    emailVerified: boolean;

    @Column({ name: 'verification_token', nullable: true })
    @Exclude()
    verificationToken: string;

    @Column({ name: 'verification_token_expires', nullable: true })
    @Exclude()
    verificationTokenExpires: Date;

    @Column({ name: 'reset_password_token', nullable: true })
    @Exclude()
    resetPasswordToken: string;

    @Column({ name: 'reset_password_expires', nullable: true })
    @Exclude()
    resetPasswordExpires: Date;

    @Column({ name: 'last_login', nullable: true })
    lastLogin: Date;

    @Column({ name: 'login_attempts', default: 0 })
    loginAttempts: number;

    @Column({ name: 'lock_until', nullable: true })
    lockUntil: Date;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt: Date;

    // Methods
    @BeforeInsert()
    @BeforeUpdate()
    async hashPassword() {
        if (this.password) {
            this.password = await bcrypt.hash(this.password, 10);
        }
    }

    async validatePassword(password: string): Promise<boolean> {
        return bcrypt.compare(password, this.password);
    }

    isLocked(): boolean {
        return !!(this.lockUntil && this.lockUntil > new Date());
    }

    incrementLoginAttempts() {
        this.loginAttempts += 1;
        if (this.loginAttempts >= 5) {
            // Lock for 15 minutes
            this.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
        }
    }

    resetLoginAttempts() {
        this.loginAttempts = 0;
        this.lockUntil = null;
    }

    // Helper methods
    get fullName(): string {
        return `${this.firstName} ${this.lastName}`.trim();
    }

    toJSON() {
        const { password, verificationToken, resetPasswordToken, ...user } = this;
        return user;
    }
}