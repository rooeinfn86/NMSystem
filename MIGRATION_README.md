# 🚀 Agent Topology Migration Guide

This guide will help you run the database migration to add topology discovery fields to your agents table.

## 📋 What This Migration Does

The migration adds these new columns to your `agents` table:
- `topology_discovery_status` - Tracks discovery state (idle, discovering, completed, failed)
- `last_topology_discovery` - Timestamp of last discovery
- `topology_discovery_config` - Discovery settings and preferences
- `discovered_devices_count` - Number of devices found
- `topology_last_updated` - Last topology update
- `topology_discovery_progress` - Discovery progress (0-100%)
- `topology_error_message` - Error details if discovery failed

## 🎯 How to Run the Migration

### **Option 1: Use the Migration Scripts (Recommended)**

#### **For Windows Users:**
1. Double-click `run_migration.bat`
2. The script will automatically:
   - Check if Python is installed
   - Run the migration
   - Show you the results

#### **For Linux/Mac Users:**
1. Open terminal in the project directory
2. Run: `./run_migration.sh`
3. The script will automatically:
   - Check if Python3 is installed
   - Run the migration
   - Show you the results

#### **For Any Platform (Python directly):**
1. Open terminal/command prompt in the project directory
2. Run: `python run_migration.py` (or `python3 run_migration.py`)

### **Option 2: Manual Commands**

If you prefer to run commands manually:

```bash
# Check current migration status
alembic current

# Run the migration
alembic upgrade head

# Verify the migration
alembic current
```

## 🔍 What to Expect

### **Successful Migration Output:**
```
🚀 Starting migration process...
📊 Checking current migration status...
Current migration: 7fe6c3b4da6c
🔄 Running migration: add_agent_topology_fields...
✅ Migration completed successfully!
🎯 Your agents table now supports topology discovery!
```

### **If Migration Fails:**
The script will show detailed error messages to help you troubleshoot.

## ⚠️ Important Notes

1. **Backup First**: Always backup your database before running migrations
2. **Test Environment**: Test the migration in a development environment first
3. **Dependencies**: Make sure `alembic` is installed: `pip install alembic`
4. **Database Connection**: Ensure your database is accessible and running

## 🚨 Troubleshooting

### **Common Issues:**

1. **"alembic not found"**
   - Install alembic: `pip install alembic`

2. **"Database connection failed"**
   - Check your database connection settings
   - Ensure the database is running

3. **"Migration already applied"**
   - This is fine! The migration will be skipped

4. **"Permission denied"**
   - Make sure you have write access to the database
   - Check your database user permissions

## 📞 Need Help?

If you encounter any issues:

1. **Check the error messages** - they usually contain helpful information
2. **Verify your database connection** - ensure the backend can connect to the database
3. **Check the logs** - look for any database-related errors

## 🎉 After Migration

Once the migration is successful:

1. **Your agents table will have the new topology fields**
2. **The backend will be ready for topology discovery features**
3. **You can proceed with the frontend implementation**

---

**Good luck with your migration! 🚀** 