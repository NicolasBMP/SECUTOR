import { Body, Controller, Header, Post, StreamableFile } from '@nestjs/common';
import { SecutorReportService } from './secutor-report.service';
import type { SecutorReportRequest } from './dto/secutor-report.interface';
import { SecutorReportValidationPipe } from './pipes/secutor-report.pipe';

@Controller('v1/secutor-report')
export class SecutorReportController {
    constructor(private readonly secutorReportService: SecutorReportService) { }

    @Post('/report')
    @Header('Content-Type', 'application/pdf')
    @Header('Content-Disposition', 'attachment; filename="reporte-secutor.pdf"')
    async getSecutorReport(@Body(SecutorReportValidationPipe) secutorReportRequest: SecutorReportRequest): Promise<StreamableFile> {
        const pdfBuffer: Buffer = await this.secutorReportService.getSecutorReport(secutorReportRequest);
        return new StreamableFile(pdfBuffer);
    }
}
