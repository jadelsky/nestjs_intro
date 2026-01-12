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
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
    },
    'access-token') // Add a bearer token for authentication
    // .addTag('users') // Optionally, add tags for better categorization of endpoints
    .build();

  const document = SwaggerModule.createDocument(app, options); // Create Swagger document
  SwaggerModule.setup('api', app, document); // Setup Swagger UI at the `/api` endpoint
  
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
  
  // Enable CORS with options (allow your frontend origin)
  app.enableCors({
    origin: 'http://localhost:5173', // frontend dev server URL
    credentials: true, // allow cookies if you use them
  });

  await app.listen(process.env.PORT ?? 3000);

}
bootstrap();
