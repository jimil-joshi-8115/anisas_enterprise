import { Request, Response } from 'express';
import { sendSuccess, sendError } from '../utils/response';
import { isValidIP, singleScanSchema, bulkScanSchema } from '../utils/validators';
import { ASNService } from '../services/asn.service';
import { asnQueue } from '../queue/asn.queue';
import { memoryStore } from '../db/prisma';
import { v4 as uuidv4 } from 'crypto';

export class ASNController {
  public static async createScan(req: Request, res: Response): Promise<Response> {
    try {
      const validation = singleScanSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || 'Invalid target IP address', 400);
      }

      const { targetIp } = validation.data;
      const scanId = `scan-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

      if (asnQueue) {
        await asnQueue.add('asn-scan', { scanId, targetIp });
      }

      // Execute scan pipeline immediately & cache result
      const result = await ASNService.executeScan(scanId, targetIp);
      return sendSuccess(res, result, 201);
    } catch (e) {
      return sendError(res, (e as Error).message, 500);
    }
  }

  public static async createBulkScan(req: Request, res: Response): Promise<Response> {
    try {
      const validation = bulkScanSchema.safeParse(req.body);
      if (!validation.success) {
        return sendError(res, validation.error.errors[0]?.message || 'Invalid bulk IP payload', 400);
      }

      const { targetIps } = validation.data;
      const scanId = `bulk-scan-${Date.now()}`;
      
      const results = await Promise.all(
        targetIps.slice(0, 10).map((ip) => {
          const itemScanId = `scan-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
          return ASNService.executeScan(itemScanId, ip);
        })
      );

      return sendSuccess(res, {
        bulkScanId: scanId,
        totalSubmitted: targetIps.length,
        processed: results.length,
        items: results
      }, 201);
    } catch (e) {
      return sendError(res, (e as Error).message, 500);
    }
  }

  public static async getScanDetails(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const scan = memoryStore.scans.get(scanId);

    if (!scan) {
      return sendError(res, 'Scan ID not found or expired', 404);
    }
    return sendSuccess(res, scan);
  }

  public static async getScanHistory(req: Request, res: Response): Promise<Response> {
    return sendSuccess(res, {
      total: memoryStore.history.length,
      history: memoryStore.history
    });
  }

  public static async getScanReport(req: Request, res: Response): Promise<Response> {
    const scanId = req.query.scanId as string;
    const format = ((req.query.format as string) || 'json').toLowerCase();

    const scan = memoryStore.scans.get(scanId);
    if (!scan) {
      return sendError(res, 'Scan ID not found', 404);
    }

    if (format === 'csv') {
      const csv = `Target IP,ASN,Organization,Country,Registry,Risk Level,Threat Score\n"${scan.targetIp}","AS${scan.asn.asnNumber}","${scan.asn.organization}","${scan.asn.country}","${scan.asn.registry}","${scan.aiEvaluation.risk_level}","${scan.aiEvaluation.risk_score}"`;
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=ANISAS_ASN_Report_${scanId}.csv`);
      return res.send(csv);
    }

    if (format === 'pdf') {
      const htmlReport = `
        <html>
          <head><style>body{font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;} h1{color:#58a6ff;} table{width:100%;border-collapse:collapse;} th,td{border:1px solid #30363d;padding:8px;text-align:left;}</style></head>
          <body>
            <h1>ANISAS Executive ASN & ISP Intelligence Report</h1>
            <p>Target IP: <strong>${scan.targetIp}</strong></p>
            <p>ASN: AS${scan.asn.asnNumber} (${scan.asn.asnName})</p>
            <p>Organization: ${scan.asn.organization}</p>
            <p>Risk Score: ${scan.aiEvaluation.risk_score}/100 (${scan.aiEvaluation.risk_level})</p>
          </body>
        </html>
      `;
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Content-Disposition', `attachment; filename=ANISAS_ASN_Report_${scanId}.html`);
      return res.send(htmlReport);
    }

    return sendSuccess(res, scan);
  }

  public static async deleteScan(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    memoryStore.scans.delete(scanId);
    return sendSuccess(res, { message: `Scan ${scanId} deleted successfully.` });
  }
}
