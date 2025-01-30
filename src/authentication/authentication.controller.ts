import {
  Controller,
  Post,
  Body,
  BadRequestException,
  UseInterceptors,
  UsePipes,
  ValidationPipe,
  UseGuards
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignInDto } from './dto/signIn.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../users/users.entity';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TransformInterceptor } from '../interceptors/transform.interceptor';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from '../users/createUser.dto';
import { Roles } from '../guards/roles/role.decorator';
import { AuthGuard } from '../guards/auth/auth.guard';

@ApiTags('Authentication')
@Controller('auth')
@Roles(UserRole.Employee, UserRole.Admin)
@UseInterceptors(TransformInterceptor)
export class AuthenticationController {
  constructor(
    private readonly authenticationService: AuthenticationService,
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) {}

  @Post('signin')
  @UsePipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  )
  @ApiOperation({ summary: 'Sign in a user into the system.' })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: {
      message: 'Success',
      data: {
        email: 'george.asiedu@gmail.com',
        accessToken: '12345',
        refreshToken: '12345',
      }
    }
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: [
      'email must be an email',
      'password must be at least 8 characters long'
    ],
  })
  @ApiBody({
    type: SignInDto,
    description: 'JSON structure to login a user',
  })
  async signIn(@Body() signInDto: SignInDto) {
    return this.authenticationService.signIn(signInDto);
  }

  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Post('refresh-token')
  @UsePipes(
    new ValidationPipe({ forbidNonWhitelisted: true, }),
  )
  @ApiOperation({ summary: 'Allow continuous user access in the system.' })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: {
      message: 'Success',
      data: {
        name: 'George Asiedu',
        email: 'george.asiedu@gmail.com',
        accessToken: '12345',
        refreshToken: '12345',
      }
    }
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: ['invalid token'],
  })
  @ApiBody({
    description: 'Refresh token string',
  })
  async refreshToken(@Body('refreshToken') refreshToken: string) {
    try {
      const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');
      const payload = this.jwtService.verify(refreshToken, {
        secret: jwtRefreshSecret,
      });
      const user = await this.usersRepository.findOne({
        where: { id: payload.sub, refreshToken },
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
      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    } catch (error) {
      if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        throw new BadRequestException('Invalid or expired refresh token');
      }
      throw new BadRequestException('Invalid refresh token');
    }
  }
}
