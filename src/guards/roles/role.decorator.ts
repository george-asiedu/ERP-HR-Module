import { SetMetadata } from '@nestjs/common';
import { UserRole } from '../../users/createUser.dto';
import { constants } from '../../utils/constants';

const ROLES_KEY = constants.ROLES_KEY;
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
