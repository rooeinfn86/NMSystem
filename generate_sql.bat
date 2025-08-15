@echo off
echo ============================================================
echo 🔧 Agent Topology Migration SQL Generator
echo ============================================================
echo.

echo 🚀 Generating SQL migration commands...
echo.

REM Run the SQL generation script
python generate_migration_sql.py

echo.
echo ============================================================
echo ✅ SQL generation complete!
echo 📁 Check the generated SQL file: agent_topology_migration.sql
echo ============================================================
echo.
pause 