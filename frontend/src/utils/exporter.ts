import { ASNScanResult } from '../types/asn';

export function downloadJSON(scan: ASNScanResult) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ANISAS_ASN_Report_${scan.targetIp}_${scan.scanId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadCSV(scan: ASNScanResult) {
  const headers = ['Target IP', 'ASN', 'ASN Name', 'Organization', 'Country', 'Registry', 'CIDR', 'Risk Level', 'Risk Score', 'VirusTotal Malicious Score', 'AbuseIPDB Score'];
  const row = [
    scan.targetIp,
    `AS${scan.asn.asnNumber}`,
    `"${scan.asn.asnName}"`,
    `"${scan.asn.organization}"`,
    scan.asn.country,
    scan.asn.registry,
    scan.asn.cidr,
    scan.aiEvaluation.risk_level,
    scan.aiEvaluation.risk_score,
    scan.threatIntel.vtMaliciousScore,
    scan.threatIntel.abuseScore
  ];
  
  const csvContent = `${headers.join(',')}\n${row.join(',')}`;
  const blob = new Blob([csvContent], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ANISAS_ASN_Report_${scan.targetIp}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadPDF(scan: ASNScanResult) {
  const windowRef = window.open('', '_blank');
  if (!windowRef) return;

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>ANISAS Executive Intelligence Report - ${scan.targetIp}</title>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0B0F19; color: #E2E8F0; padding: 40px; margin: 0; }
          .header { border-bottom: 2px solid #3B82F6; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
          .title { font-size: 28px; font-weight: bold; color: #60A5FA; }
          .badge { padding: 6px 16px; border-radius: 20px; font-weight: bold; text-transform: uppercase; font-size: 14px; }
          .badge-low { background: #065F46; color: #34D399; }
          .badge-high { background: #991B1B; color: #FCA5A5; }
          .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
          .card { background: #111827; border: 1px solid #1F2937; padding: 20px; border-radius: 8px; }
          .label { color: #94A3B8; font-size: 13px; text-transform: uppercase; margin-bottom: 4px; }
          .val { font-size: 18px; font-weight: 600; color: #F8FAFC; }
          table { width: 100%; border-collapse: collapse; margin-top: 20px; }
          th, td { border: 1px solid #1F2937; padding: 12px; text-align: left; }
          th { background: #1E293B; color: #94A3B8; }
        </style>
      </head>
      <body>
        <div class="header">
          <div>
            <div class="title">ANISAS Cyber Intelligence Platform</div>
            <div style="color: #94A3B8;">Module 01: ASN & ISP Executive Profile Report</div>
          </div>
          <div class="badge ${scan.aiEvaluation.risk_level === 'HIGH' || scan.aiEvaluation.risk_level === 'CRITICAL' ? 'badge-high' : 'badge-low'}">
            Risk: ${scan.aiEvaluation.risk_level} (${scan.aiEvaluation.risk_score}/100)
          </div>
        </div>

        <div class="grid">
          <div class="card">
            <div class="label">Target IPv4/IPv6</div>
            <div class="val">${scan.targetIp}</div>
          </div>
          <div class="card">
            <div class="label">Autonomous System (ASN)</div>
            <div class="val">AS${scan.asn.asnNumber} - ${scan.asn.asnName}</div>
          </div>
          <div class="card">
            <div class="label">Organization / ISP</div>
            <div class="val">${scan.asn.organization}</div>
          </div>
          <div class="card">
            <div class="label">Registry & Location</div>
            <div class="val">${scan.asn.registry} (${scan.asn.country}) - ${scan.geo.city}, ${scan.geo.region}</div>
          </div>
        </div>

        <div class="card">
          <div class="label">AI Executive Threat Summary</div>
          <p style="font-size: 15px; line-height: 1.6; color: #CBD5E1;">${scan.aiEvaluation.ai_executive_summary}</p>
        </div>

        <h3>BGP & Network Routing Intelligence</h3>
        <table>
          <tr><th>CIDR Subnet</th><th>Global Upstream Peers</th><th>Announced Networks</th></tr>
          <tr>
            <td>${scan.asn.cidr}</td>
            <td>${scan.bgp.peers.join(', ')}</td>
            <td>${scan.bgp.announcedNetworks.join(', ')}</td>
          </tr>
        </table>
      </body>
    </html>
  `;

  windowRef.document.write(html);
  windowRef.document.close();
  setTimeout(() => windowRef.print(), 500);
}
