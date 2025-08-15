# Google Cloud Deployment Guide

## Overview

This guide walks you through deploying the updated Cisco AI system (with agent support) to Google Cloud Run and Cloud SQL.

## Prerequisites

### Required Tools
- **Google Cloud SDK**: Install from [cloud.google.com/sdk](https://cloud.google.com/sdk)
- **kubectl**: For running database migrations
- **Docker**: For local testing (optional)

### Google Cloud Setup
- **Project**: Active Google Cloud project
- **Billing**: Enabled billing account
- **APIs**: Cloud Run, Cloud SQL, Secret Manager enabled
- **Permissions**: Owner or Editor role

## Quick Deployment

### Option 1: Automated Script (Recommended)

#### Linux/macOS
```bash
# Make script executable
chmod +x deploy-to-cloud.sh

# Edit configuration
nano deploy-to-cloud.sh
# Update PROJECT_ID, REGION, DATABASE_INSTANCE

# Run deployment
./deploy-to-cloud.sh
```

#### Windows
```cmd
# Edit configuration
notepad deploy-to-cloud.bat
# Update PROJECT_ID, REGION, DATABASE_INSTANCE

# Run deployment
deploy-to-cloud.bat
```

### Option 2: Manual Deployment

## Step-by-Step Manual Deployment

### 1. Configure Google Cloud

```bash
# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable secretmanager.googleapis.com
```

### 2. Database Setup

#### Create Cloud SQL Instance
```bash
# Create PostgreSQL instance
gcloud sql instances create cisco-ai-database \
    --database-version=POSTGRES_14 \
    --tier=db-f1-micro \
    --region=us-central1 \
    --storage-type=SSD \
    --storage-size=10GB \
    --backup-start-time=02:00 \
    --maintenance-window-day=SUN \
    --maintenance-window-hour=03:00

# Create database
gcloud sql databases create cisco_ai_db --instance=cisco-ai-database

# Create user
gcloud sql users create cisco_ai_user \
    --instance=cisco-ai-database \
    --password=YOUR_SECURE_PASSWORD
```

#### Store Database Password
```bash
# Create secret
echo -n "YOUR_SECURE_PASSWORD" | gcloud secrets create db-password --data-file=-

# Verify secret
gcloud secrets versions access latest --secret="db-password"
```

### 3. Service Account Setup

```bash
# Create service account
gcloud iam service-accounts create cisco-ai-service \
    --display-name="Cisco AI Service Account" \
    --description="Service account for Cisco AI Cloud Run services"

# Grant permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:cisco-ai-service@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudsql.client"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:cisco-ai-service@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

### 4. Deploy Backend

```bash
# Navigate to backend directory
cd cisco_ai_backend

# Get database connection info
DB_HOST=$(gcloud sql instances describe cisco-ai-database --format="value(connectionName)")
DB_PASSWORD=$(gcloud secrets versions access latest --secret="db-password")

# Deploy to Cloud Run
gcloud run deploy cisco-ai-backend \
    --source . \
    --region us-central1 \
    --platform managed \
    --allow-unauthenticated \
    --add-cloudsql-instances $DB_HOST \
    --set-env-vars "DATABASE_URL=postgresql://cisco_ai_user:$DB_PASSWORD@/cisco_ai_db?host=/cloudsql/$DB_HOST" \
    --set-env-vars "SECRET_KEY=your-secret-key-here" \
    --set-env-vars "ALGORITHM=HS256" \
    --set-env-vars "ACCESS_TOKEN_EXPIRE_MINUTES=30" \
    --memory 1Gi \
    --cpu 1 \
    --max-instances 10 \
    --timeout 300 \
    --service-account=cisco-ai-service@YOUR_PROJECT_ID.iam.gserviceaccount.com

# Get backend URL
BACKEND_URL=$(gcloud run services describe cisco-ai-backend --region us-central1 --format="value(status.url)")
echo "Backend URL: $BACKEND_URL"
```

### 5. Deploy Frontend

```bash
# Navigate to frontend directory
cd ../cisco-config-ui

# Deploy to Cloud Run
gcloud run deploy cisco-ai-frontend \
    --source . \
    --region us-central1 \
    --platform managed \
    --allow-unauthenticated \
    --set-env-vars "REACT_APP_API_BASE_URL=$BACKEND_URL" \
    --memory 512Mi \
    --cpu 1 \
    --max-instances 5 \
    --timeout 60

# Get frontend URL
FRONTEND_URL=$(gcloud run services describe cisco-ai-frontend --region us-central1 --format="value(status.url)")
echo "Frontend URL: $FRONTEND_URL"
```

### 6. Run Database Migrations

```bash
# Create migration job
cat > migration-job.yaml << EOF
apiVersion: run.googleapis.com/v1
kind: Job
metadata:
  name: cisco-ai-migration
spec:
  template:
    spec:
      template:
        spec:
          containers:
          - image: gcr.io/YOUR_PROJECT_ID/cisco-ai-backend
            command: ["python", "-m", "alembic", "upgrade", "head"]
            env:
            - name: DATABASE_URL
              value: "postgresql://cisco_ai_user:$DB_PASSWORD@/cisco_ai_db?host=/cloudsql/$DB_HOST"
            - name: SECRET_KEY
              value: "your-secret-key-here"
            - name: ALGORITHM
              value: "HS256"
            - name: ACCESS_TOKEN_EXPIRE_MINUTES
              value: "30"
          serviceAccountName: cisco-ai-service@YOUR_PROJECT_ID.iam.gserviceaccount.com
EOF

# Run migration
kubectl apply -f migration-job.yaml
kubectl wait --for=condition=complete job/cisco-ai-migration --timeout=300s

# Clean up
rm migration-job.yaml
kubectl delete job cisco-ai-migration
```

## Configuration

### Environment Variables

#### Backend Environment Variables
```bash
DATABASE_URL=postgresql://user:password@/dbname?host=/cloudsql/connection-name
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

#### Frontend Environment Variables
```bash
REACT_APP_API_BASE_URL=https://your-backend-url.com
```

### Security Configuration

#### Secret Management
```bash
# Store sensitive data in Secret Manager
echo -n "your-secret-key" | gcloud secrets create backend-secret-key --data-file=-
echo -n "your-jwt-secret" | gcloud secrets create jwt-secret --data-file=-

# Reference secrets in Cloud Run
gcloud run services update cisco-ai-backend \
    --update-secrets SECRET_KEY=backend-secret-key:latest \
    --region us-central1
```

#### IAM Permissions
```bash
# Grant additional permissions if needed
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:cisco-ai-service@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/logging.logWriter"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:cisco-ai-service@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/monitoring.metricWriter"
```

## Monitoring and Logging

### View Logs
```bash
# Backend logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=cisco-ai-backend" --limit=50

# Frontend logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=cisco-ai-frontend" --limit=50
```

### Monitor Performance
```bash
# View service metrics
gcloud monitoring metrics list --filter="metric.type:run.googleapis.com"

# Check service status
gcloud run services describe cisco-ai-backend --region us-central1
```

## Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Test database connectivity
gcloud sql connect cisco-ai-database --user=cisco_ai_user

# Check connection string
echo "postgresql://cisco_ai_user:password@/cisco_ai_db?host=/cloudsql/connection-name"
```

#### Service Deployment Failures
```bash
# Check build logs
gcloud builds list --limit=10

# View service logs
gcloud run services logs read cisco-ai-backend --region us-central1
```

#### Migration Issues
```bash
# Check migration status
gcloud run jobs executions list --job=cisco-ai-migration --region us-central1

# View migration logs
gcloud run jobs executions logs read EXECUTION_NAME --region us-central1
```

### Performance Optimization

#### Resource Scaling
```bash
# Scale backend for higher load
gcloud run services update cisco-ai-backend \
    --memory 2Gi \
    --cpu 2 \
    --max-instances 20 \
    --region us-central1

# Scale frontend
gcloud run services update cisco-ai-frontend \
    --memory 1Gi \
    --cpu 1 \
    --max-instances 10 \
    --region us-central1
```

#### Database Optimization
```bash
# Upgrade database tier
gcloud sql instances patch cisco-ai-database \
    --tier=db-n1-standard-1

# Enable connection pooling
gcloud sql instances patch cisco-ai-database \
    --database-flags max_connections=100
```

## Cost Optimization

### Resource Recommendations
- **Backend**: Start with 1Gi memory, 1 CPU
- **Frontend**: 512Mi memory, 1 CPU
- **Database**: db-f1-micro for development, db-n1-standard-1 for production

### Cost Monitoring
```bash
# View current costs
gcloud billing accounts list
gcloud billing budgets list

# Set up billing alerts
gcloud billing budgets create \
    --billing-account=YOUR_BILLING_ACCOUNT \
    --budget-amount=100USD \
    --threshold-rule=percent=0.5 \
    --threshold-rule=percent=0.9
```

## Security Best Practices

### Network Security
```bash
# Restrict access to Cloud SQL
gcloud sql instances patch cisco-ai-database \
    --authorized-networks=YOUR_IP_RANGE

# Enable SSL for database connections
gcloud sql instances patch cisco-ai-database \
    --require-ssl
```

### Application Security
```bash
# Rotate secrets regularly
gcloud secrets versions add db-password --data-file=<(echo -n "new-password")

# Update service with new secrets
gcloud run services update cisco-ai-backend \
    --update-secrets DB_PASSWORD=db-password:latest \
    --region us-central1
```

## Backup and Recovery

### Database Backups
```bash
# Create manual backup
gcloud sql backups create --instance=cisco-ai-database

# List backups
gcloud sql backups list --instance=cisco-ai-database

# Restore from backup
gcloud sql instances restore-backup cisco-ai-database \
    --backup-instance=cisco-ai-database \
    --backup-id=BACKUP_ID
```

### Application Recovery
```bash
# Rollback to previous revision
gcloud run services update-traffic cisco-ai-backend \
    --to-revisions=REVISION_NAME=100 \
    --region us-central1

# View revision history
gcloud run revisions list --service=cisco-ai-backend --region us-central1
```

## Agent Configuration

After deployment, update your agent configuration files with the new backend URL:

```json
{
  "backend_url": "https://your-backend-url.com",
  "agent_token": "your-agent-token",
  "agent_name": "My Network Agent",
  "heartbeat_interval": 30
}
```

## Support

For additional support:
- **Google Cloud Documentation**: [cloud.google.com/run/docs](https://cloud.google.com/run/docs)
- **Cloud SQL Documentation**: [cloud.google.com/sql/docs](https://cloud.google.com/sql/docs)
- **Cisco AI Support**: support@cisco-ai.com

## Conclusion

Your Cisco AI system is now deployed to Google Cloud with full agent support. The system includes:

- ✅ **Backend**: FastAPI service with agent management
- ✅ **Frontend**: React application with agent deployment UI
- ✅ **Database**: PostgreSQL with company token tables
- ✅ **Security**: Service accounts and secret management
- ✅ **Monitoring**: Logging and performance metrics
- ✅ **Scalability**: Auto-scaling Cloud Run services

The agent system is ready for deployment across your network infrastructure! 🚀 