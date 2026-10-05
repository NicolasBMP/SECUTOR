import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { envs } from './config/envs';
import { WebIdentifierModule } from './web-identifier/web-identifier.module';
import { CommonModule } from './common/common.module';
import { HeaderIdentifierModule } from './header-identifier/header-identifier.module';
import { CookieIdentifierModule } from './cookie-identifier/cookie-identifier.module';
import { DataIdentifierModule } from './data-identifier/data-identifier.module';
import { SecurityIdentifierModule } from './security-identifier/security-identifier.module';
import { VulnerabilityIdentifierModule } from './vulnerability-identifier/vulnerability-identifier.module';
import { DomainIdentifierModule } from './domain-identifier/domain-identifier.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { FingerprintThrottlerGuard } from './common/guards/fingerprint-guard';
import { FingerprintMiddleware } from './common/middlewares/fingerprint-middleware';
import { ContentIdentifierModule } from './content-identifier/content-identifier.module';
import { SecutorReportModule } from './secutor-report/secutor-report.module';
// import { HeaderIdentifierController } from './header-identifier/header-identifier.controller';
// import { CookieIdentifierController } from './cookie-identifier/cookie-identifier.controller';

@Module({
  imports: [
    //CONFIGURACIONES GENERALES
    ScheduleModule.forRoot(),
    ConfigModule.forRoot({
      isGlobal: true
    }),
    //CONFIGURACION DE BASE DE DATOS

    //CONFIGURACION DE CORREO
    MailerModule.forRoot({
      transport: {
        host: envs.email_host,
        port: envs.email_port,
        ignoreTLS: true,
        secure: true,
        auth: {
          user: envs.email_user,
          pass: envs.email_pass
        },
        preview: false,
        defaults: {
          from: `"No Reply" ${envs.email_user}`
        }
      }
    }),
    //CONFIGURACION DE RATE LIMIT (FingerprintMiddleware + FingerprintThrottlerGuard)
    ThrottlerModule.forRoot([
      {
        ttl: envs.rate_limit_ttl,
        limit: envs.rate_limit_limit
      }
    ]),
    //CARGA DE MODULOS 
    WebIdentifierModule, HeaderIdentifierModule, CookieIdentifierModule, DataIdentifierModule, SecurityIdentifierModule, 
    VulnerabilityIdentifierModule, DomainIdentifierModule, ContentIdentifierModule, SecutorReportModule, CommonModule
  ],
  controllers: [],
  providers: [{
    provide: APP_GUARD,
    useClass: FingerprintThrottlerGuard
  }]
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(FingerprintMiddleware).forRoutes('{*path}');
    //consumer.apply(FingerprintMiddleware).forRoutes(HeaderIdentifierController, CookieIdentifierController);
    //consumer.apply(FingerprintMiddleware).forRoutes('domain-identifier', 'header-identifier/{*path}');
    //consumer.apply(FingerprintMiddleware).forRoutes({ path: 'domain-identifier/analyze', method: RequestMethod.POST }, { path: 'vulnerability-identifier/{*path}', method: RequestMethod.GET });
    //consumer.apply(FingerprintMiddleware).exclude('health', { path: 'auth/login', method: RequestMethod.POST }).forRoutes('{*path}');
  }
}
