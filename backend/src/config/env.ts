import dotenv from 'dotenv';
dotenv.config();

export const env = {
  PORT: process.env.PORT || '5000',
  NODE_ENV: process.env.NODE_ENV || 'development',
  JWT_SECRET: process.env.JWT_SECRET || 'anisas_enterprise_super_secret_jwt_key_2026',
  DATABASE_URL: process.env.DATABASE_URL || 'postgresql://anisas:anisas_secure_password@localhost:5432/anisas_db?schema=public',
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
  AI_SERVICE_URL: process.env.AI_SERVICE_URL || 'http://localhost:9000',
  
  // API Keys
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || '',
  SHODAN_API_KEY: process.env.SHODAN_API_KEY || '',
  IPINFO_TOKEN: process.env.IPINFO_TOKEN || '',
  ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY || '',
  GREYNOISE_API_KEY: process.env.GREYNOISE_API_KEY || '',
  SECURITYTRAILS_API_KEY: process.env.SECURITYTRAILS_API_KEY || ''
};
