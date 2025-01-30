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
import { CreateUserDto } from '../users/createUser.dto';
import { AuthGuard } from '../guards/auth/auth.guard';
import {
  BadRequestExample,
  LoginBadRequestExample,
  LoginResponseExample, RegularLoginExample, RememberMeLoginExample,
  UserResponseExample,
} from '../utils/userResponse';
import { UsersService } from 'src/users/users.service';

@ApiTags('Authentication')
@Controller('auth')
@UseInterceptors(TransformInterceptor)
export class AuthenticationController {
  constructor(
    private authenticationService: AuthenticationService,
    @InjectRepository(User) private usersRepository: Repository<User>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private usersService: UsersService
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
  async signup(@Body() user: CreateUserDto): Promise<CreateUserDto & User> {
    return await this.usersService.signup(user);
  }

  @Post('signin')
  @UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, }),)
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
