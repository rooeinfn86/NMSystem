@echo off
echo ============================================================
echo 🔧 Agent Topology Migration Runner (Windows)
echo ============================================================
echo.

echo 🚀 Starting migration process...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found! Please install Python first.
    echo.
    pause
    exit /b 1
)

echo ✅ Python found, running migration...
echo.

REM Run the migration script
python run_migration.py

echo.
echo ============================================================
if errorlevel 1 (
    echo ❌ Migration failed! Check the error messages above.
) else (
    echo ✅ Migration completed successfully!
    echo 🎯 Your agents table now supports topology discovery!
)
echo ============================================================
echo.
pause 