import { BadRequestException, ConflictException, Injectable } from '@nestjs/common';
import { SignInDto } from './dto/signIn.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../users/users.entity';
import { QueryFailedError, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import { CreateUserDto } from './dto/createUser.dto';
import { TwoFactorDto } from './dto/twoFactor.dto';

export interface SignInResponse {
  accessToken: string;
  refreshToken: string;
}

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailerService: MailerService,
  ) {}

  async signup(user: CreateUserDto): Promise<Partial<CreateUserDto>> {
    const existingUser = await this.usersRepository.findOneBy({ email: user.email.toLowerCase() });
    if (existingUser) {
      throw new ConflictException('Email is already in use');
    }

    const twoFactorCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.password = await User.hashPassword(user.password);
    const newUser = this.usersRepository.create({ ...user, twoFactorCode });

    try {
      await this.usersRepository.save(newUser);

      try {
        await this.mailerService.sendMail({
          to: newUser.email,
          subject: 'Your 2FA Verification Code',
          text: `Your 2FA code is: ${twoFactorCode}`,
        });
      } catch (emailError) {
        throw new BadRequestException(`Error sending email: ${emailError.message}`);
      }
      const { password, ...userResponse } = newUser;
      return userResponse;
    } catch (error) {
      if (error instanceof QueryFailedError && error.driverError.code === '23505') {
        throw new ConflictException('Email is already in use');
      }
      throw error;
    }
  }

  async verifyTwoFactorCode(body: TwoFactorDto) {
    const user = await this.usersRepository.findOne({ where: { email: body.email.toLowerCase() } });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.twoFactorCode !== body.twoFactorCode) {
      throw new BadRequestException('Invalid 2FA code');
    }

    user.isVerified = true;
    user.twoFactorCode = null;
    await this.usersRepository.save(user);
  }

  async signIn(signInDto: SignInDto): Promise<SignInResponse> {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtExpiry = this.configService.get<string>('JWT_EXPIRY');
    const jwtRefreshExpiry = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN');
    const longExpiry = this.configService.get<string>('JWT_REMEMBER_ME_EXPIRY');
    const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    const { email, password, rememberMe } = signInDto;

    const user = await this.usersRepository.findOne({
      where: { email: email.toLowerCase() },
      select: ['id', 'email', 'password', 'isVerified']
    });

    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }

    if (!user.isVerified) {
      throw new BadRequestException('Account not verified. Please verify your email.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new BadRequestException('Invalid password');
    }

    const expiration = rememberMe ? longExpiry : jwtExpiry ;

    const payload = {
      email: user.email,
      name: user.name,
      role: user.role,
      isVerified: user.isVerified,
      id: user.id,
      sub: user.id
    };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: expiration,
      secret: jwtSecret,
    });
    const refreshToken = this.jwtService.sign(payload, {
      secret: jwtRefreshSecret,
      expiresIn: jwtRefreshExpiry,
    });

    user.refreshToken = refreshToken;
    await this.usersRepository.save(user);

    return { accessToken, refreshToken };
  }
}