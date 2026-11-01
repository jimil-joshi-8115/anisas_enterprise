-- Remove Module 05 (Wireless Infrastructure Intelligence) data models.
-- Module renumbering: former Module 06 (AI Risk Engine) -> Module 05,
-- former Module 07 (Unified SOC Dashboard) -> Module 06.
--
-- NOTE: node.js / prisma CLI is not available in this environment, so this
-- migration was hand-written. Apply it with:
--   cd backend && npx prisma migrate dev --name remove_module05_wireless
-- (Prisma will detect this folder as a pending migration.)

DROP TABLE IF EXISTS "WirelessAccessPoint";
DROP TABLE IF EXISTS "WirelessClient";
DROP TABLE IF EXISTS "WirelessVendor";
DROP TABLE IF EXISTS "WirelessAuthentication";
DROP TABLE IF EXISTS "WirelessBehavior";
DROP TABLE IF EXISTS "WirelessAnomaly";
DROP TABLE IF EXISTS "WirelessRisk";
DROP TABLE IF EXISTS "WirelessAssessment";
