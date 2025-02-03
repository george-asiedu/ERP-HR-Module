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
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { VerificationCodeDto } from './dto/verificationCode.dto';
import { RefreshTokenDto } from './dto/refreshToken.dto';

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

  decodeToken(token: string) {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    try {
      return this.jwtService.verify(token, { secret: jwtSecret });
    } catch (error) {
      throw new BadRequestException('Invalid or expired token');
    }
  }

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
      const {
        password, passwordResetCode, canResetPassword,
        passwordResetExpires, refreshToken,
        twoFactorCode: _twoFactorCode, ...userResponse
      } = newUser;
      return userResponse;
    } catch (error) {
      if (error instanceof QueryFailedError && error.driverError.code === '23505') {
        throw new ConflictException('Email is already in use');
      }
      throw error;
    }
  }

  async verifyTwoFactorCode(body: TwoFactorDto, token: string) {
    const payload = this.decodeToken(token);
    if (!payload || !payload.userId) {
      throw new BadRequestException('Invalid token');
    }

    const user = await this.usersRepository.findOne({ where: { id: payload.userId } });
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

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const user = await this.usersRepository.findOne({ where: { email: forgotPasswordDto.email.toLowerCase() } });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.passwordResetCode = resetCode;
    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);

    await this.usersRepository.save(user);

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Password Reset Code',
      text: `Your password reset code is: ${resetCode}`,
    });
  }

  async verifyResetCode(verificationCode: VerificationCodeDto, token: string) {
    const payload = this.decodeToken(token);
    if (!payload || !payload.userId) {
      throw new BadRequestException('Invalid token');
    }

    const user = await this.usersRepository.findOne({ where: { id: payload.userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (
      !user || user.passwordResetCode !== verificationCode.verificationCode
      || !user.passwordResetExpires || new Date() > user.passwordResetExpires
    ) {
      throw new BadRequestException('Invalid or expired verification code.');
    }

    user.passwordResetCode = null;
    user.passwordResetExpires = null;
    user.canResetPassword = true;

    await this.usersRepository.save(user);
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, token: string) {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      const payload = this.jwtService.verify(token, { secret: jwtSecret });

      const user = await this.usersRepository.findOne({
        where: { email: payload.email.toLowerCase() },
      });

      if (!user || !user.canResetPassword) {
        throw new BadRequestException('Password reset not allowed. Verify your reset code first.');
      }
      if (resetPasswordDto.newPassword !== resetPasswordDto.confirmNewPassword) {
        throw new BadRequestException('Passwords do not match.');
      }

      user.password = await bcrypt.hash(resetPasswordDto.newPassword, 10);
      user.canResetPassword = false;

      await this.usersRepository.save(user);
    } catch (error) {
      if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        throw new BadRequestException('Invalid or expired token');
      }
      throw new BadRequestException('Error resetting password');
    }
  }

  async refreshToken(refreshToken: RefreshTokenDto) {
    try {
      const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');
      const payload = this.jwtService.verify(refreshToken.refreshToken, {
        secret: jwtRefreshSecret,
      });
      const user = await this.usersRepository.findOne({
        where: { id: payload.sub, refreshToken: refreshToken.refreshToken },
      });

      if (!user) {
        throw new BadRequestException('Invalid token');
      }

      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      const accessExpiration = this.configService.get<string>('JWT_EXPIRY');
      const refreshExpiration = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN');

      const newAccessToken = this.jwtService.sign(
        { email: user.email, sub: user.id },
        {
          secret: jwtSecret,
          expiresIn: accessExpiration,
        },
      );

      const newRefreshToken = this.jwtService.sign(
        { email: user.email, sub: user.id },
        {
          secret: jwtRefreshSecret,
          expiresIn: refreshExpiration,
        },
      );

      user.refreshToken = newRefreshToken;
      await this.usersRepository.save(user);

      return { accessToken: newAccessToken, refreshToken: newRefreshToken }
    } catch (error) {
      if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        throw new BadRequestException('Invalid or expired refresh token');
      }
      throw new BadRequestException('Invalid refresh token');
    }
  }
}