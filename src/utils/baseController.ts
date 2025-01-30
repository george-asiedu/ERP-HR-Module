import { UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthGuard } from '../guards/auth/auth.guard';
import { TransformInterceptor } from '../interceptors/transform.interceptor';

@UseGuards(AuthGuard)
@UseInterceptors(TransformInterceptor)
export abstract class BaseController {}