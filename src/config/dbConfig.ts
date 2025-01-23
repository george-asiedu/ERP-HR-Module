import { PostgresConnectionOptions} from 'typeorm/driver/postgres/PostgresConnectionOptions';
import { ConfigService } from '@nestjs/config';
import { User } from '../users/users.entity';

export const pgConfig = (configService: ConfigService): PostgresConnectionOptions => ({
  type: 'postgres',
  host: configService.get<string>('DB_HOST', 'localhost'),
  port: configService.get<number>('DB_PORT', 5432),
  username: configService.get<string>('DB_USERNAME', 'default_user'),
  password: configService.get<string>('DB_PASSWORD', 'default_password'),
  database: configService.get<string>('DB_NAME', 'default_db'),
  url: configService.get<string>('DB_URL'),
  entities: [User],
  synchronize: configService.get<string>('NODE_ENV') !== 'production'
    ? configService.get<boolean>('DB_SYNC', true)
    : false,
});