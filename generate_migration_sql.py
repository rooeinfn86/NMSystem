#!/usr/bin/env python3
"""
SQL Migration Generator
This script generates the exact SQL commands needed to add topology discovery fields to the agents table.
No dependencies required - just generates the SQL for you to run manually.
"""

import os
import sys
from pathlib import Path

def generate_migration_sql():
    """Generate SQL migration commands."""
    
    print("=" * 80)
    print("🔧 Agent Topology Migration SQL Generator")
    print("=" * 80)
    print()
    
    print("📋 This script generates the SQL commands to add topology discovery fields to your agents table.")
    print("📝 You can run these SQL commands directly in your database.")
    print()
    
    # Generate the SQL commands
    sql_commands = [
        "-- ===================================================",
        "-- Agent Topology Discovery Migration SQL",
        "-- ===================================================",
        "-- Run these commands in your database to add topology discovery fields",
        "--",
        "-- 1. Add topology_discovery_status column",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_discovery_status VARCHAR DEFAULT 'idle';",
        "",
        "-- 2. Add last_topology_discovery column",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_topology_discovery TIMESTAMP;",
        "",
        "-- 3. Add topology_discovery_config column",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_discovery_config JSONB;",
        "",
        "-- 4. Add discovered_devices_count column",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS discovered_devices_count INTEGER DEFAULT 0;",
        "",
        "-- 5. Add topology_last_updated column",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_last_updated TIMESTAMP;",
        "",
        "-- 6. Add topology_discovery_progress column",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_discovery_progress INTEGER DEFAULT 0;",
        "",
        "-- 7. Add topology_error_message column",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS topology_error_message TEXT;",
        "",
        "-- ===================================================",
        "-- Verification Commands",
        "-- ===================================================",
        "-- Run these to verify the columns were added:",
        "",
        "-- Check table structure",
        "\\d agents;",
        "",
        "-- Check if new columns exist",
        "SELECT column_name, data_type, is_nullable, column_default",
        "FROM information_schema.columns",
        "WHERE table_name = 'agents' AND table_schema = 'public'",
        "ORDER BY ordinal_position;",
        "",
        "-- ===================================================",
        "-- Migration Complete!",
        "-- ==================================================="
    ]
    
    # Print the SQL commands
    print("🚀 Generated SQL Migration Commands:")
    print()
    for command in sql_commands:
        print(command)
    
    print()
    print("=" * 80)
    print("📋 How to Use These SQL Commands:")
    print("=" * 80)
    print()
    print("1. 📊 Connect to your database (PostgreSQL)")
    print("2. 📝 Copy and paste the SQL commands above")
    print("3. 🚀 Execute them one by one or all at once")
    print("4. ✅ Verify the columns were added using the verification commands")
    print()
    print("💡 Tip: You can run these in:")
    print("   - psql command line")
    print("   - pgAdmin")
    print("   - Any PostgreSQL client")
    print()
    print("⚠️  Important Notes:")
    print("   - Backup your database before running migrations")
    print("   - Test in a development environment first")
    print("   - The IF NOT EXISTS clause prevents errors if columns already exist")
    print()
    
    # Save to file
    sql_file = "agent_topology_migration.sql"
    try:
        with open(sql_file, 'w') as f:
            for command in sql_commands:
                f.write(command + '\n')
        
        print(f"💾 SQL commands saved to: {sql_file}")
        print(f"📁 File location: {Path.cwd() / sql_file}")
        print()
        print("🎯 You can now:")
        print("   1. Run the SQL commands in your database")
        print("   2. Or use the generated SQL file")
        print()
        
    except Exception as e:
        print(f"⚠️  Could not save to file: {e}")
        print("📝 Copy the SQL commands above manually")
    
    print("=" * 80)
    print("🚀 Ready to migrate! Run the SQL commands in your database.")
    print("=" * 80)

def main():
    """Main function."""
    generate_migration_sql()

if __name__ == "__main__":
    main() 