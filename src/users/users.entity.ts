import {
  Column,
  Entity,
  PrimaryGeneratedColumn
} from 'typeorm';
import * as bcrypt from 'bcrypt';
import { UserRole } from '../authentication/dto/createUser.dto';

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

  @Column({ nullable: true })
  public refreshToken!: string;

  @Column({ type: 'varchar', nullable: true })
  twoFactorCode!: string | null;

  @Column({ default: false })
  isVerified!: boolean;

  @Column({ type: 'varchar', length: 6, nullable: true })
  passwordResetCode!: string | null;

  @Column({ type: 'timestamp', nullable: true })
  passwordResetExpires!: Date | null;

  @Column({ type: 'boolean', default: false })
  canResetPassword!: boolean;

  @Column({ type: 'varchar', nullable: true })
  image?: string | null;

  public static async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  }
}