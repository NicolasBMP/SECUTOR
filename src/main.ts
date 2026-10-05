import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, ValidationPipe } from '@nestjs/common';
import { json } from 'express';
import { envs } from './config/envs';
import { HeaderInterceptor } from './common/interceptors/header.interceptor';
import helmet from 'helmet';

async function main() {
  const logger = new Logger('API SECUTOR');
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    //origin: envs.cors.split(','),
    Credential: true,
    METHODS: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'QUERY'],
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-Fingerprint-Id'],
    exposedHeaders: ['X-Total-Time', 'X-Total-Items', 'X-Total-Size', 'X-Request-Id', 'X-App-Version', 'X-RAM-Memory', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']
  });
  app.useGlobalInterceptors(new HeaderInterceptor());
  if (envs.microservice_name) {
    app.setGlobalPrefix(`${envs.microservice_name}`);
  }
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    disableErrorMessages: false,
    transform: true,
    transformOptions: {
      enableImplicitConversion: true
    }
  }));
  const jsonLimit = process.env.JSON_LIMIT ?? '20mb';
  app.use(json({ limit: jsonLimit }));
  app.use(helmet());
  app.enableShutdownHooks();
  await app.listen(envs.port);
  logger.log(`API port: ${envs.port} info`);
}
main();
