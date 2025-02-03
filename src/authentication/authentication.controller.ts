import {
  Controller,
  Post,
  Body,
  UseInterceptors,
  UsePipes,
  ValidationPipe,
  UseGuards, Query,
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { SignInDto } from './dto/signIn.dto';
import { TransformInterceptor } from '../interceptors/transform.interceptor';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiParam, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CreateUserDto } from './dto/createUser.dto';
import { AuthGuard } from '../guards/auth/auth.guard';
import {
  BadRequestExample,
  LoginBadRequestExample,
  LoginResponseExample, RegularLoginExample, RememberMeLoginExample,
  UserResponseExample,
} from '../utils/userResponse';
import { TwoFactorDto } from './dto/twoFactor.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { VerificationCodeDto } from './dto/verificationCode.dto';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { RefreshTokenDto } from './dto/refreshToken.dto';

@ApiTags('Authentication')
@Controller('auth')
@UseInterceptors(TransformInterceptor)
export class AuthenticationController {
  constructor(private authenticationService: AuthenticationService) {}

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
  @ApiOperation({ summary: 'Verifies the 2FA code sent to the user\'s email using token.' })
  @ApiParam({ name: 'token', description: 'The token for the user to verify their account.' })
  @ApiBody({ type: TwoFactorDto, description: '2FA code to verify a user\'s account' })
  @ApiResponse({
    status: 200,
    description: 'Success.',
    example: { message: 'Success' }
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: { message: 'Invalid 2FA code or user not found.' }
  })
  async verifyTwoFactorCode(@Query('token') token: string, @Body() twoFactorDto: TwoFactorDto) {
    return await this.authenticationService.verifyTwoFactorCode(twoFactorDto, token);
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
    status: 200,
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

  @Post('forgot-password')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  @ApiOperation({ summary: 'Send a password reset verification code to the user\'s email.' })
  @ApiBody({ type: ForgotPasswordDto, description: 'JSON structure to to send verification code.' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: { message: 'Success' }
  })@ApiResponse({
    status: 400,
    description: 'Bad Request',
    example: { message: 'Invalid email.' }
  })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authenticationService.forgotPassword(forgotPasswordDto);
  }

  @Post('verify-reset-code')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  @ApiOperation({ summary: 'Verify the 6-digit reset code before resetting the password.' })
  @ApiParam({ name: 'token', description: 'The token for the user to verify their reset code.' })
  @ApiBody({
    type: VerificationCodeDto,
    description: 'JSON structure to verify the reset code, which includes the verification code.'
  })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: { message: 'Success' }
  })@ApiResponse({
    status: 400,
    description: 'Bad Request',
    example: { message: 'Invalid reset code.' }
  })
  async verifyResetCode(@Query('token') token: string, @Body() verificationCodeDto: VerificationCodeDto) {
    return this.authenticationService.verifyResetCode(verificationCodeDto, token);
  }

  @Post('reset-password')
  @UsePipes(new ValidationPipe({ whitelist: true }))
  @ApiOperation({ summary: 'Reset the user\'s password after verification.' })
  @ApiParam({ name: 'token', description: 'The token to verify the user' })
  @ApiBody({ type: ResetPasswordDto, description: 'JSON structure to to reset password.' })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: { message: 'Success' }
  })@ApiResponse({
    status: 400,
    description: 'Bad Request',
    example: { message: 'Password does not match.' }
  })
  async resetPassword(@Query('token') token: string, @Body() resetPasswordDto: ResetPasswordDto) {
    return this.authenticationService.resetPassword(resetPasswordDto, token);
  }

  @ApiBearerAuth()
  @UseGuards(AuthGuard)
  @Post('refresh-token')
  @UsePipes(new ValidationPipe({ forbidNonWhitelisted: true, }))
  @ApiOperation({ summary: 'Allow continuous user access in the system using a refresh token.' })
  @ApiBody({ type: RefreshTokenDto, description: 'Refresh token string' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: LoginResponseExample
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: { message: 'Invalid token.' },
  })
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authenticationService.refreshToken(refreshTokenDto);
  }
}
