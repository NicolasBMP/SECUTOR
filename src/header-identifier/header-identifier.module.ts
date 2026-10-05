import { Module } from '@nestjs/common';
import { HeaderIdentifierService } from './header-identifier.service';
import { HeaderIdentifierController } from './header-identifier.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [HeaderIdentifierController],
  providers: [HeaderIdentifierService],
  exports: [HeaderIdentifierService]
})
export class HeaderIdentifierModule {}
