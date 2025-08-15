#!/bin/bash

echo "============================================================"
echo "🔧 Agent Topology Migration Runner (Linux/Mac)"
echo "============================================================"
echo ""

echo "🚀 Starting migration process..."
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found! Please install Python3 first."
    echo ""
    exit 1
fi

echo "✅ Python3 found, running migration..."
echo ""

# Make the script executable
chmod +x run_migration.py

# Run the migration script
python3 run_migration.py

echo ""
echo "============================================================"
if [ $? -eq 0 ]; then
    echo "✅ Migration completed successfully!"
    echo "🎯 Your agents table now supports topology discovery!"
else
    echo "❌ Migration failed! Check the error messages above."
fi
echo "============================================================"
echo "" 