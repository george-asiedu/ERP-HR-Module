import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { constants } from './utils/constants';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true});
  app.setGlobalPrefix(constants.globalPrefix);
  app.useGlobalPipes(new ValidationPipe());

  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') || 3000;

  const options = new DocumentBuilder()
    .setTitle(constants.swaggerDocsTitle)
    .setDescription(constants.swaggerDocsDescription)
    .setVersion(constants.swaggerDocsVersion)
    .addServer(`${constants.localUrl}${port}/`, 'Local environment')
    .addServer(constants.productionUrl, 'Production')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup(constants.swaggerDocsPath, app, document);

  await app.listen(port);
}
bootstrap();