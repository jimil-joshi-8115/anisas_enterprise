import { Response } from 'express';

export interface ApiResponse<T = any> {
  success: boolean;
  data: T | null;
  error: string | null;
  timestamp: string;
}

export function sendSuccess<T>(res: Response, data: T, statusCode: number = 200): Response {
  const payload: ApiResponse<T> = {
    success: true,
    data,
    error: null,
    timestamp: new Date().toISOString()
  };
  return res.status(statusCode).json(payload);
}

export function sendError(res: Response, message: string, statusCode: number = 400): Response {
  const payload: ApiResponse = {
    success: false,
    data: null,
    error: message,
    timestamp: new Date().toISOString()
  };
  return res.status(statusCode).json(payload);
}
