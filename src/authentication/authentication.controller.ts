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
import { CreateUserDto } from './dto/createUser.dto';
import { AuthGuard } from '../guards/auth/auth.guard';
import {
  BadRequestExample,
  LoginBadRequestExample,
  LoginResponseExample, RegularLoginExample, RememberMeLoginExample,
  UserResponseExample,
} from '../utils/userResponse';
import { TwoFactorDto } from './dto/twoFactor.dto';

@ApiTags('Authentication')
@Controller('auth')
@UseInterceptors(TransformInterceptor)
export class AuthenticationController {
  constructor(
    private authenticationService: AuthenticationService,
    @InjectRepository(User) private usersRepository: Repository<User>,
    private jwtService: JwtService,
    private configService: ConfigService
  ) {}

  @Post('signup')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
  @ApiOperation({ summary: 'Creates a new user into the system.' })
  @ApiBody({ type: CreateUserDto, description: 'JSON structure to create a new user.' })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: UserResponseExample,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: BadRequestExample,
  })
  async signup(@Body() user: CreateUserDto): Promise<Partial<CreateUserDto>> {
    return await this.authenticationService.signup(user);
  }

  @Post('verify-2fa')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, }))
  @ApiOperation({ summary: 'Verifies the 2FA code sent to the user\'s email.' })
  @ApiResponse({
    status: 200,
    description: 'Success.',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid 2FA code or user not found.',
  })
  async verifyTwoFactorCode(@Body() twoFactorDto: TwoFactorDto) {
    return await this.authenticationService.verifyTwoFactorCode(twoFactorDto);
  }

  @Post('signin')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, }))
  @ApiOperation({ summary: 'Sign in a user into the system.' })
  @ApiBody({
    type: SignInDto,
    description: 'JSON structure to login a user.',
    examples: {regularLogin: RegularLoginExample, rememberMeLogin: RememberMeLoginExample},
  })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: LoginResponseExample
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request',
    example: LoginBadRequestExample
  })
  async signIn(@Body() signInDto: SignInDto) {
    return this.authenticationService.signIn(signInDto);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Post('refresh-token')
  @UsePipes(new ValidationPipe({ forbidNonWhitelisted: true, }))
  @ApiOperation({ summary: 'Allow continuous user access in the system.' })
  @ApiBody({ description: 'Refresh token string' })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: LoginResponseExample
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: ['invalid token'],
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
      return { accessToken: newAccessToken, refreshToken: newRefreshToken }
    } catch (error) {
      if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
        throw new BadRequestException('Invalid or expired refresh token');
      }
      throw new BadRequestException('Invalid refresh token');
    }
  }
}
