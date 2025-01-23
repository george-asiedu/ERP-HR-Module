import {
  BeforeInsert,
  BeforeUpdate,
  Column,
  Entity,
  PrimaryGeneratedColumn
} from 'typeorm';
import * as bcrypt from 'bcrypt';
import { UserRole } from './createUser.dto';

const BCRYPT_SALT_ROUNDS = 10;

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  public id!: number;

  @Column()
  public name!: string;

  @Column({ unique: true })
  public email!: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.Employee,
  })
  public role!: UserRole;

  @Column()
  public password!: string;

  @BeforeInsert()
  @BeforeUpdate()
  async handlePasswordHashing(): Promise<void> {
    if (this.password) {
      this.password = await User.hashPassword(this.password);
    }
  }

  private static async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
    return bcrypt.hash(password, salt);
  }
}