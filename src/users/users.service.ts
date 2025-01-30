import { ConflictException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './users.entity';
import { QueryFailedError, Repository } from 'typeorm';
import { CreateUserDto } from './createUser.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {}

  async getAllUsers(): Promise<User[]> {
    return await this.usersRepository.find();
  }

  async getUserById(id: number): Promise<User | null> {
    return await this.usersRepository.findOneBy({ id });
  }

  async signup(user: CreateUserDto): Promise<CreateUserDto & User> {
    const existingUser = await this.usersRepository.findOneBy({ email: user.email.toLowerCase() });
    if (existingUser) {
      throw new ConflictException('Email is already in use');
    }

    const newUser = this.usersRepository.create(user);

    try {
      return await this.usersRepository.save(newUser);
    } catch (error) {
      if (error instanceof QueryFailedError && error.driverError.code === '23505') {
        throw new ConflictException('Email is already in use');
      }
      throw error;
    }
  }

  async deleteUser(id: number): Promise<void> {
    await this.usersRepository.delete(id);
  }
}
