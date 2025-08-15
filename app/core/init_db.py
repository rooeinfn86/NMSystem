from sqlalchemy.orm import Session
from app.models.base import Company, User
from app.core.database import engine
from app.models.base import Base
import hashlib

def init_db():
    Base.metadata.create_all(bind=engine)
    return 1, 1  # Default company and user IDs

def init_benchmarks(db: Session):
    """Initialize CIS benchmark data in the database"""
    try:
        # Check if benchmarks already exist
        existing_benchmarks = db.query(CISBenchmark).count()
        if existing_benchmarks > 0:
            print("Benchmarks already initialized")
            return

        # Define CIS benchmarks
        benchmarks = [
            {
                "benchmark_id": "1.1",
                "title": "Ensure the default admin password is changed",
                "description": "Change the default admin password to a strong, unique password",
                "severity": "High",
                "category": "Access Control"
            },
            {
                "benchmark_id": "1.2",
                "title": "Ensure password complexity is enabled",
                "description": "Enable password complexity requirements",
                "severity": "Medium",
                "category": "Access Control"
            },
            {
                "benchmark_id": "2.1",
                "title": "Ensure SSH is configured securely",
                "description": "Configure SSH with secure settings",
                "severity": "High",
                "category": "Network Security"
            },
            {
                "benchmark_id": "2.2",
                "title": "Ensure unused services are disabled",
                "description": "Disable unnecessary network services",
                "severity": "Medium",
                "category": "Network Security"
            },
            {
                "benchmark_id": "3.1",
                "title": "Ensure logging is enabled",
                "description": "Enable system logging",
                "severity": "Low",
                "category": "Logging"
            },
            {
                "benchmark_id": "3.2",
                "title": "Ensure log rotation is configured",
                "description": "Configure log rotation to prevent disk space issues",
                "severity": "Low",
                "category": "Logging"
            }
        ]

        # Add benchmarks to database
        for benchmark in benchmarks:
            db_benchmark = CISBenchmark(**benchmark)
            db.add(db_benchmark)
        
        db.commit()
        print(f"Initialized {len(benchmarks)} CIS benchmarks")
        
    except Exception as e:
        print(f"Error initializing benchmarks: {str(e)}")
        db.rollback()
        raise

if __name__ == "__main__":
    company_id, user_id = init_db()
    print(f"Default company ID: {company_id}")
    print(f"Default user ID: {user_id}") 