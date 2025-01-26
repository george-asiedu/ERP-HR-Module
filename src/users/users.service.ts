import { ConflictException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './users.entity';
import { QueryFailedError, Repository } from 'typeorm';
import { CreateUserDto } from './createUser.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {}

  async findAll(): Promise<{data: User[]}> {
    const res = await this.usersRepository.find();
    return {
      data: res
    }
  }

  async findOne(id: number): Promise<User | null> {
    return await this.usersRepository.findOneBy({ id });
  }

  async create(user: CreateUserDto): Promise<CreateUserDto & User> {
    const newUser: CreateUserDto & User = this.usersRepository.create(user);
    newUser.password = await bcrypt.hash(user.password, await bcrypt.genSalt());
    const existingUser = await this.usersRepository.findOneBy({ email: user.email });
    if (existingUser) {
      throw new ConflictException('Email is already in use');
    }
    try {
      return await this.usersRepository.save(newUser);
    } catch (error) {
      if (error instanceof QueryFailedError && error.driverError.code === '23505') {
        throw new ConflictException('Email is already in use');
      }
      throw error;
    }

  }

  async remove(id: number): Promise<void> {
    await this.usersRepository.delete(id);
  }
}
