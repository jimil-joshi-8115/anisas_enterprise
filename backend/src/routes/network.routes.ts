import { Router } from 'express';
import { NetworkController } from '../controllers/network.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';

const router = Router();

// REST APIs under /api/v1/network
router.post('/scan', authenticateJWT, NetworkController.executeRecon);
router.get('/:scanId', authenticateJWT, NetworkController.getReconDetails);
router.get('/:scanId/topology', authenticateJWT, NetworkController.getTopology);
router.get('/:scanId/services', authenticateJWT, NetworkController.getServices);
router.get('/:scanId/dns', authenticateJWT, NetworkController.getDNS);

export default router;
