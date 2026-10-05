import { Module } from '@nestjs/common';
import { SecutorReportService } from './secutor-report.service';
import { SecutorReportController } from './secutor-report.controller';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  controllers: [SecutorReportController],
  providers: [SecutorReportService],
  exports: [SecutorReportService]
})
export class SecutorReportModule {}
