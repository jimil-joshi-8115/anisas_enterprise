import { Request, Response } from 'express';
import { sendSuccess, sendError } from '../utils/response';
import { PerimeterService } from '../services/perimeter.service';
import { memoryStore } from '../db/prisma';

export class PerimeterController {
  public static async executePerimeterScan(req: Request, res: Response): Promise<Response> {
    try {
      const { scanId } = req.body;
      if (!scanId) {
        return sendError(res, 'Scan ID is required to execute Module 03', 400);
      }

      const result = await PerimeterService.executePerimeterAnalysis(scanId);
      return sendSuccess(res, result, 200);
    } catch (e) {
      return sendError(res, (e as Error).message, 500);
    }
  }

  public static async getPerimeterDetails(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module3`;
    let perimeter = memoryStore.scans.get(key);

    if (!perimeter) {
      perimeter = await PerimeterService.executePerimeterAnalysis(scanId);
    }

    return sendSuccess(res, perimeter);
  }

  public static async getWAFDetails(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module3`;
    let perimeter = memoryStore.scans.get(key);

    if (!perimeter) {
      perimeter = await PerimeterService.executePerimeterAnalysis(scanId);
    }

    return sendSuccess(res, {
      waf: perimeter.waf,
      firewall: perimeter.firewall,
      ids: perimeter.ids
    });
  }

  public static async getPostureScore(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module3`;
    let perimeter = memoryStore.scans.get(key);

    if (!perimeter) {
      perimeter = await PerimeterService.executePerimeterAnalysis(scanId);
    }

    return sendSuccess(res, perimeter.securityPostureScore);
  }

  public static async getRecommendations(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module3`;
    let perimeter = memoryStore.scans.get(key);

    if (!perimeter) {
      perimeter = await PerimeterService.executePerimeterAnalysis(scanId);
    }

    return sendSuccess(res, {
      recommendations: perimeter.recommendations,
      evasionAwarenessGuide: perimeter.evasionAwarenessGuide
    });
  }
}
