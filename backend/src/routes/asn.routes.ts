import { Router } from 'express';
import { ASNController } from '../controllers/asn.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';

const router = Router();

// REST APIs under /api/v1/asn
router.post('/scan', authenticateJWT, ASNController.createScan);
router.post('/bulk', authenticateJWT, ASNController.createBulkScan);
router.get('/history', authenticateJWT, ASNController.getScanHistory);
router.get('/report', authenticateJWT, ASNController.getScanReport);
router.get('/:scanId', authenticateJWT, ASNController.getScanDetails);
router.delete('/:scanId', authenticateJWT, ASNController.deleteScan);

export default router;
