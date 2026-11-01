import axios from 'axios';
import { ASNScanResult, ScanHistoryItem } from '../types/asn';

const API_BASE = '/api/v1/asn';

export async function initiateScan(targetIp: string): Promise<ASNScanResult> {
  const res = await axios.post(`${API_BASE}/scan`, { targetIp });
  return res.data.data;
}

export async function initiateBulkScan(targetIps: string[]): Promise<any> {
  const res = await axios.post(`${API_BASE}/bulk`, { targetIps });
  return res.data.data;
}

export async function fetchScan(scanId: string): Promise<ASNScanResult> {
  const res = await axios.get(`${API_BASE}/${scanId}`);
  return res.data.data;
}

export async function fetchScanHistory(): Promise<{ total: number; history: ScanHistoryItem[] }> {
  const res = await axios.get(`${API_BASE}/history`);
  return res.data.data;
}

export async function deleteScanRecord(scanId: string): Promise<void> {
  await axios.delete(`${API_BASE}/${scanId}`);
}
