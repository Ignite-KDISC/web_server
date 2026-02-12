#!/usr/bin/env python3
"""
Backup script for uploads folder
Creates a timestamped zip file of the uploads directory
and stores it in /backup folder
"""

import os
import zipfile
import datetime
import logging
from pathlib import Path

# Configuration
UPLOADS_DIR = "/opt/web_server/uploads"
BACKUP_DIR = "/backup"
LOG_FILE = "/var/log/uploads_backup.log"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def create_backup():
    """Create a zip backup of the uploads directory"""
    try:
        # Create backup directory if it doesn't exist
        Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
        
        # Check if uploads directory exists
        if not os.path.exists(UPLOADS_DIR):
            logging.error(f"Uploads directory not found: {UPLOADS_DIR}")
            return False
        
        # Generate timestamp for backup filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"uploads_backup_{timestamp}.zip"
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        logging.info(f"Starting backup of {UPLOADS_DIR}")
        logging.info(f"Backup will be saved to: {backup_path}")
        
        # Create zip file
        file_count = 0
        total_size = 0
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the uploads directory
            for root, dirs, files in os.walk(UPLOADS_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Calculate relative path for zip archive
                    arcname = os.path.relpath(file_path, os.path.dirname(UPLOADS_DIR))
                    
                    # Add file to zip
                    zipf.write(file_path, arcname)
                    file_count += 1
                    total_size += os.path.getsize(file_path)
        
        # Get backup file size
        backup_size = os.path.getsize(backup_path)
        backup_size_mb = backup_size / (1024 * 1024)
        
        logging.info(f"Backup completed successfully!")
        logging.info(f"Files backed up: {file_count}")
        logging.info(f"Total size: {total_size / (1024 * 1024):.2f} MB")
        logging.info(f"Backup size: {backup_size_mb:.2f} MB")
        
        # Optional: Delete old backups (keep last 30 days)
        cleanup_old_backups(days=30)
        
        return True
        
    except Exception as e:
        logging.error(f"Backup failed: {str(e)}", exc_info=True)
        return False

def cleanup_old_backups(days=30):
    """Remove backup files older than specified days"""
    try:
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
        deleted_count = 0
        
        for filename in os.listdir(BACKUP_DIR):
            if filename.startswith("uploads_backup_") and filename.endswith(".zip"):
                file_path = os.path.join(BACKUP_DIR, filename)
                file_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                
                if file_time < cutoff_date:
                    os.remove(file_path)
                    deleted_count += 1
                    logging.info(f"Deleted old backup: {filename}")
        
        if deleted_count > 0:
            logging.info(f"Cleaned up {deleted_count} old backup file(s)")
            
    except Exception as e:
        logging.warning(f"Failed to cleanup old backups: {str(e)}")

if __name__ == "__main__":
    logging.info("=" * 60)
    logging.info("Starting uploads backup process")
    logging.info("=" * 60)
    
    success = create_backup()
    
    if success:
        logging.info("Backup process completed successfully")
        exit(0)
    else:
        logging.error("Backup process failed")
        exit(1)
