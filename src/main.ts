import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

    // Swagger setup
    const options = new DocumentBuilder()
    .setTitle('NestJS auth API') // Set your API title
    .setDescription('API description') // Provide the API description
    .setVersion('1.0') // Set the version
    // .addTag('users') // Optionally, add tags for better categorization of endpoints
    .build();

  const document = SwaggerModule.createDocument(app, options); // Create Swagger document
  SwaggerModule.setup('api', app, document); // Setup Swagger UI at the `/api` endpoint
  
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
  
  await app.listen(process.env.PORT ?? 3000);

}
bootstrap();
