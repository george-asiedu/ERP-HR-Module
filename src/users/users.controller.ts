import {
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
  Req,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from './users.entity';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from './createUser.dto';
import { Roles } from '../guards/roles/role.decorator';
import { RequestInterface } from '../guards/auth/auth.guard';
import {
  GetAllUsersResponseExample,
  UserResponseExample
} from '../utils/userResponse';
import { BaseController } from '../utils/baseController';

@ApiTags('Users')
@ApiBearerAuth()
@Controller('users')
export class UsersController extends BaseController {
  constructor(private usersService: UsersService) {
    super();
  }

  @Get('all-users')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Displays all users in the system.' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: GetAllUsersResponseExample
  })
  async getAllUsers(): Promise<User[]> {
    return await this.usersService.getAllUsers();
  }

  @Get(':id')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Retrieves a user by ID.' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: UserResponseExample
  })
  @ApiResponse({
    status: 400,
    description: 'Bad Request.',
    example: 'Invalid user ID format.'
  })
  async getUserById(@Param('id', ParseIntPipe) id: number): Promise<User | null> {
    return await this.usersService.getUserById(id);
  }

  @Get('profile')
  @ApiOperation({ summary: 'Retrieves the profile of the logged-in user.' })
  @ApiResponse({
    status: 200,
    description: 'Success',
    example: UserResponseExample
  })
  async getProfile(@Req() req: RequestInterface): Promise<User | null> {
    return await this.usersService.getUserById(req.user?.id);
  }

  @Delete(':id')
  @Roles(UserRole.Admin)
  @ApiOperation({ summary: 'Deletes a user by ID' })
  @ApiResponse({ status: 200, description: 'Success' })
  @ApiResponse({ status: 400, description: 'Bad Request', example: 'Invalid user ID format.' })
  async deleteUser(@Param('id') id: number): Promise<any> {
    return this.usersService.deleteUser(id);
  }
}