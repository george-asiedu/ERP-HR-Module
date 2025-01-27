import { Body, Controller, Delete, Get, Param, ParseIntPipe, Post, UsePipes, ValidationPipe } from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from './users.entity';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CreateUserDto, UserRole } from './createUser.dto';
import { Roles } from '../guards/roles/role.decorator';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('all-users')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Displays all users in the system.' })
  @ApiResponse({
    status: 200,
    description: 'List of all users in the system.',
    example: {
      id: 1,
      name: 'George Asiedu',
      email: 'george.asiedu@gmail.com',
      role: 'admin'
    }
  })
  async getAllUsers(): Promise<{data: User[]}> {
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
    description: 'User has been successfully created.',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number', example: 1 },
        name: { type: 'string', example: 'George Asiedu' },
        email: { type: 'string', example: 'george.asiedu@gmail.com' },
        role: { type: 'string', example: 'admin' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 400 },
        message: {
          type: 'array',
          items: { type: 'string' },
          example: [
            'name should not be empty',
            'email must be an email',
            'password must be at least 8 characters long'
          ],
        },
        error: { type: 'string', example: 'Bad Request' },
      },
    },
  })
  @ApiResponse({ status: 403, description: 'Forbidden.' })
  @ApiBody({
    type: CreateUserDto,
    description: 'JSON structure to create a new user.',
  })
  async signup(@Body() user: CreateUserDto): Promise<CreateUserDto & User> {
    return await this.usersService.signup(user);
  }

  @Get(':id')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Retrieves a user by ID.' })
  @ApiResponse({
    status: 200,
    description: 'User ID found successfully.',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'number', example: 1 },
        name: { type: 'string', example: 'John Doe' },
        email: { type: 'string', example: 'johndoe@example.com' },
        role: { type: 'string', example: 'admin' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 400 },
        message: { type: 'string', example: 'Invalid user ID format.' },
        error: { type: 'string', example: 'Bad Request' },
      },
    },
  })
  async getUserById(@Param('id', ParseIntPipe) id: number): Promise<User | null> {
    return await this.usersService.getUserById(id);
  }

  @Delete(':id')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Deletes a user by ID.' })
  @ApiResponse({
    status: 200,
    description: 'User successfully deleted.',
    schema: {
      type: 'object',
      properties: {
        message: { type: 'string', example: 'User deleted successfully.' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    schema: {
      type: 'object',
      properties: {
        statusCode: { type: 'number', example: 400 },
        message: { type: 'string', example: 'Invalid user ID format.' },
        error: { type: 'string', example: 'Bad Request' },
      },
    },
  })
  async deleteUser(@Param('id') id: number): Promise<any> {
    return this.usersService.deleteUser(id);
  }
}