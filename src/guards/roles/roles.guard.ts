import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { UserRole } from '../../authentication/dto/createUser.dto';
import { constants } from '../../utils/constants';

@Injectable()
export class RolesGuard implements CanActivate {
  private ROLES_KEY: string = constants.ROLES_KEY;
  private unauthorizedError: string = constants.UnauthorizedError

  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(this.ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest();
    const hasRole = requiredRoles.some(
      (role) => user.role?.includes(role)
    );

    if (!hasRole) {
      throw new UnauthorizedException(this.unauthorizedError);
    }

    return true;
  }
}