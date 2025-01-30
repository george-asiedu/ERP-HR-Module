import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Post, UseGuards,
  UseInterceptors,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from './users.entity';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CreateUserDto, UserRole } from './createUser.dto';
import { Roles } from '../guards/roles/role.decorator';
import { TransformInterceptor } from '../interceptors/transform.interceptor';
import { AuthGuard } from '../guards/auth/auth.guard';

@ApiTags('Users')
@Controller('users')
@UseInterceptors(TransformInterceptor)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Get('all-users')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Displays all users in the system.' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin'
    }
  })
  async getAllUsers(): Promise<User[]> {
    return await this.usersService.getAllUsers();
  }

  @Post('signup')
  @Roles(UserRole.Admin, UserRole.Employee)
  @UsePipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  )
  @ApiOperation({ summary: 'Creates a new user into the system.' })
  @ApiResponse({
    status: 201,
    description: 'Success',
    example: {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin'
    }
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: [
      'name should not be empty',
      'email must be an email',
      'password must be at least 8 characters long'
    ],
  })
  @ApiBody({
    type: CreateUserDto,
    description: 'JSON structure to create a new user.',
  })
  async signup(@Body() user: CreateUserDto): Promise<CreateUserDto & User> {
    return await this.usersService.signup(user);
  }

  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Get(':id')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Retrieves a user by ID.' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin'
    }
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: 'Invalid user ID format.'
  })
  async getUserById(@Param('id', ParseIntPipe) id: number): Promise<User | null> {
    return await this.usersService.getUserById(id);
  }

  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Delete(':id')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Deletes a user by ID.' })
  @ApiResponse({
    status: 200,
    description: 'Success'
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: 'Invalid user ID format.'
  })
  async deleteUser(@Param('id') id: number): Promise<any> {
    return this.usersService.deleteUser(id);
  }
}