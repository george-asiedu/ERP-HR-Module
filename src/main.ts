import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Get the port from the environment using ConfigService
  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') || 3000;

  const options = new DocumentBuilder()
    .setTitle('ERP System API Documentation')
    .setDescription('API for managing the HR module in an ERP system')
    .setVersion('1.0.0')
    .addServer(`http://localhost:${port}/`, 'Local environment')
    // .addTag('')
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('api-docs', app, document);

  app.enableCors();
  await app.listen(port);
}
bootstrap();