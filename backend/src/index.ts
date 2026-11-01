import app from './app';
import { env } from './config/env';
import { logger } from './utils/logger';

const port = parseInt(env.PORT, 10);

app.listen(port, () => {
  logger.info(`ANISAS Enterprise Backend running on port ${port}`);
  logger.info(`Module 01 REST API listening on http://localhost:${port}/api/v1/asn`);
});
