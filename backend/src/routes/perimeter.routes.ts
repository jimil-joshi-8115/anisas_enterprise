import { Router } from 'express';
import { PerimeterController } from '../controllers/perimeter.controller';
import { authenticateJWT } from '../middlewares/auth.middleware';

const router = Router();

// REST APIs under /api/v1/perimeter
router.post('/scan', authenticateJWT, PerimeterController.executePerimeterScan);
router.get('/:scanId', authenticateJWT, PerimeterController.getPerimeterDetails);
router.get('/:scanId/waf', authenticateJWT, PerimeterController.getWAFDetails);
router.get('/:scanId/score', authenticateJWT, PerimeterController.getPostureScore);
router.get('/:scanId/recommendations', authenticateJWT, PerimeterController.getRecommendations);

export default router;
