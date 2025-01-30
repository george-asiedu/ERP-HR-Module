import { BadRequestException, Injectable } from '@nestjs/common';
import { SignInDto } from './dto/signIn.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../users/users.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

export interface SignInResponse {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signIn(signInDto: SignInDto): Promise<SignInResponse> {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtExpiry = this.configService.get<string>('JWT_EXPIRY');
    const jwtRefreshExpiry = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN');

    const { email, password } = signInDto;

    const user = await this.usersRepository.findOne({
      where: { email: email.toLowerCase() },
      select: ['id', 'email', 'password']
    });

    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid email or password');
    }

    const payload = { email: user.email, sub: user.id };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: jwtExpiry,
      secret: jwtSecret,
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: jwtSecret,
      expiresIn: jwtRefreshExpiry,
    });

    user.refreshToken = refreshToken;
    await this.usersRepository.save(user);

    return { accessToken, refreshToken };
  }
}