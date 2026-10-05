import { Module } from '@nestjs/common';
import { CookieIdentifierService } from './cookie-identifier.service';
import { CookieIdentifierController } from './cookie-identifier.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [CookieIdentifierController],
  providers: [CookieIdentifierService],
  exports: [CookieIdentifierService]
})
export class CookieIdentifierModule {}
