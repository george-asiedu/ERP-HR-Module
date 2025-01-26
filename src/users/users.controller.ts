import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from './users.entity';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CreateUserDto } from './createUser.dto';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('all-users')
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
  async findAll(): Promise<{data: User[]}> {
    return await this.usersService.findAll();
  }

  @Post('create-user')
  @UsePipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  )
  @ApiOperation({ summary: 'Creates a new user in the system.' })
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
  async create(@Body() user: CreateUserDto): Promise<CreateUserDto & User> {
    return await this.usersService.create(user);
  }

  @Get(':id')
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
  async findOne(@Param('id') id: number): Promise<User | null> {
    return await this.usersService.findOne(id);
  }

  @Delete(':id')
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
  async remove(@Param('id') id: number): Promise<any> {
    return this.usersService.remove(id);
  }
}