import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import asnRoutes from './routes/asn.routes';
import networkRoutes from './routes/network.routes';
import perimeterRoutes from './routes/perimeter.routes';
import { apiLimiter } from './middlewares/rateLimiter.middleware';
import { sendSuccess } from './utils/response';

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(apiLimiter);

// Health Check
app.get('/health', (req, res) => {
  return sendSuccess(res, {
    status: 'ONLINE',
    system: 'ANISAS Enterprise Backend',
    version: '1.0.0'
  });
});

// Register Module 01 ASN & ISP Intelligence Routes
app.use('/api/v1/asn', asnRoutes);

// Register Module 02 Network Reconnaissance Routes
app.use('/api/v1/network', networkRoutes);

// Register Module 03 Security Perimeter Detection Routes
app.use('/api/v1/perimeter', perimeterRoutes);

export default app;
