import { Request, Response } from 'express';
import { sendSuccess, sendError } from '../utils/response';
import { NetworkService } from '../services/network.service';
import { memoryStore } from '../db/prisma';

export class NetworkController {
  public static async executeRecon(req: Request, res: Response): Promise<Response> {
    try {
      const { scanId } = req.body;
      if (!scanId) {
        return sendError(res, 'Scan ID is required to execute Module 02', 400);
      }

      const result = await NetworkService.executeRecon(scanId);
      return sendSuccess(res, result, 200);
    } catch (e) {
      return sendError(res, (e as Error).message, 500);
    }
  }

  public static async getReconDetails(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module2`;
    let recon = memoryStore.scans.get(key);

    if (!recon) {
      // Execute automatically if not cached yet
      recon = await NetworkService.executeRecon(scanId);
    }

    return sendSuccess(res, recon);
  }

  public static async getTopology(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module2`;
    let recon = memoryStore.scans.get(key);

    if (!recon) {
      recon = await NetworkService.executeRecon(scanId);
    }

    return sendSuccess(res, recon.topology);
  }

  public static async getServices(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module2`;
    let recon = memoryStore.scans.get(key);

    if (!recon) {
      recon = await NetworkService.executeRecon(scanId);
    }

    return sendSuccess(res, {
      hosts: recon.hosts,
      services: recon.portServices
    });
  }

  public static async getDNS(req: Request, res: Response): Promise<Response> {
    const { scanId } = req.params;
    const key = `${scanId}-module2`;
    let recon = memoryStore.scans.get(key);

    if (!recon) {
      recon = await NetworkService.executeRecon(scanId);
    }

    return sendSuccess(res, {
      records: recon.dnsRecords,
      subdomains: recon.subdomains
    });
  }
}
