import { Injectable, InternalServerErrorException, Logger } from '@nestjs/common';
import { SecutorReportRequest } from './dto/secutor-report.interface';
import { PdfReportBuilder } from './helpers/pdf-report.builder';

@Injectable()
export class SecutorReportService {
    private readonly logger = new Logger('SECUTOR-REPORT-SERVICE');
    constructor() { }

    async getSecutorReport(secutorReportRequest: SecutorReportRequest): Promise<Buffer> {
        try {
            const builder = new PdfReportBuilder(secutorReportRequest);
            return builder.build();
        } catch (error: any) {
            this.logger.error(`Error crítico: ${error.stack}`);
            throw new InternalServerErrorException(`Se produjo un error al generar el reporte: ${error}`);
        }
    }
}
