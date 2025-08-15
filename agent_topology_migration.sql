-- ===================================================
-- Agent Topology Discovery Migration SQL
-- ===================================================
-- Run these commands in your database to add topology discovery fields
--
-- 1. Add topology_discovery_status column
ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_discovery_status VARCHAR DEFAULT 'idle';

-- 2. Add last_topology_discovery column
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_topology_discovery TIMESTAMP;

-- 3. Add topology_discovery_config column
ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_discovery_config JSONB;

-- 4. Add discovered_devices_count column
ALTER TABLE agents ADD COLUMN IF NOT EXISTS discovered_devices_count INTEGER DEFAULT 0;

-- 5. Add topology_last_updated column
ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_last_updated TIMESTAMP;

-- 6. Add topology_discovery_progress column
ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_discovery_progress INTEGER DEFAULT 0;

-- 7. Add topology_error_message column
ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_error_message TEXT;

-- ===================================================
-- Verification Commands
-- ===================================================
-- Run these to verify the columns were added:

-- Check table structure
\d agents;

-- Check if new columns exist
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'agents' AND table_schema = 'public'
ORDER BY ordinal_position;

-- ===================================================
-- Migration Complete!
-- ===================================================
