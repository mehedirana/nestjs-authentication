// src/auth/strategies/jwt-refresh.strategy.ts
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

import { UsersService } from '../../users/users.service';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt.refreshSecret'),
      passReqToCallback: true,
    });
  }

  async validate(req: any, payload: any) {
    const refreshToken = req.get('Authorization').replace('Bearer ', '').trim();
    
    const user = await this.usersService.findOne(payload.sub);
    
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return {
      ...user,
      refreshToken,
    };
  }
}