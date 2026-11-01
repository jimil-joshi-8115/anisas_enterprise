export interface ASNInfo {
  asnNumber: number;
  asnName: string;
  organization: string;
  country: string;
  registry: string;
  cidr: string;
  prefixes: string[];
  allocationDate: string;
  description: string;
}

export interface WhoisRecord {
  registrar: string;
  owner: string;
  creationDate: string;
  expirationDate: string;
  updatedDate: string;
  netRange: string;
  cidr: string;
  abuseEmail: string;
  rawData: string;
}

export interface RDAPRecord {
  networkName: string;
  abuseContact: string;
  adminContact: string;
  country: string;
  organization: string;
  address: string;
  registrationStatus: string;
  rawData: any;
}

export interface BGPRecord {
  originAsn: number;
  asnName: string;
  prefixes: string[];
  peers: string[];
  announcedNetworks: string[];
  routingInfo: string;
}

export interface GeoRecord {
  hostname: string;
  reverseDns: string;
  country: string;
  latitude: number;
  longitude: number;
  city: string;
  region: string;
  timezone: string;
  isp: string;
  org: string;
  asnNumber: number;
  asnName: string;
  registry: string;
}

export interface ThreatIntel {
  vtMaliciousScore: number;
  abuseScore: number;
  greyNoiseClassification: string;
  confidenceScore: number;
  abuseReportsCount: number;
  threatCategories: string[];
  rawData: any;
}

export interface AIEvaluation {
  target_ip: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_category: string;
  asset_criticality: number;
  anomaly_score: number;
  confidence_score: number;
  ai_executive_summary: string;
}

export interface ASNScanResult {
  scanId: string;
  targetIp: string;
  status: 'PENDING' | 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  progress: number;
  currentModule: string;
  asn: ASNInfo;
  whois: WhoisRecord;
  rdap: RDAPRecord;
  bgp: BGPRecord;
  geo: GeoRecord;
  threatIntel: ThreatIntel;
  aiEvaluation: AIEvaluation;
  module02Payload: any;
  createdAt: string;
}

export interface ScanHistoryItem {
  id: string;
  scanId: string;
  targetIp: string;
  summary: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  riskScore: number;
  timestamp: string;
}
