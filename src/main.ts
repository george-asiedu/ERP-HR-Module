import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') || 3000;

  const options = new DocumentBuilder()
    .setTitle('ERP System API Documentation')
    .setDescription('API for managing the HR module in an ERP system')
    .setVersion('1.0.0')
    .addServer(`http://localhost:${port}/`, 'Local environment')
    .addServer('https://erp-system-hr-module.onrender.com', 'Production')
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('api-docs', app, document);

  app.enableCors();
  await app.listen(port);
}
bootstrap();