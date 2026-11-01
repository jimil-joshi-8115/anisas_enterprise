import { z } from 'zod';

// IPv4 / IPv6 validation regex patterns
const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)$/;
const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

export function isValidIP(ip: string): boolean {
  const cleanIp = ip.trim();
  return ipv4Regex.test(cleanIp) || ipv6Regex.test(cleanIp);
}

export const singleScanSchema = z.object({
  targetIp: z.string().refine((ip) => isValidIP(ip), {
    message: 'Invalid IPv4 or IPv6 address provided'
  })
});

export const bulkScanSchema = z.object({
  targetIps: z.array(z.string().refine((ip) => isValidIP(ip), {
    message: 'One or more invalid IP addresses in bulk input'
  })).min(1, 'At least one IP address is required')
});
