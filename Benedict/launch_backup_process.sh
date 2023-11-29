#!/bin/bash

# Log file location with date and hour
BACKUP_LOG="/home/logs/backup_log_$(date +'%Y-%m-%d_%H-%M-%S').log"

# Current timestamp
echo "Backup process started at $(date)" | tee -a "$BACKUP_LOG"

# Path to the backup script for server data
SERVER_BACKUP_SCRIPT="/home/launch_backup_server.sh"

# Path to the backup script for coreCA data
CORECA_BACKUP_SCRIPT="/home/launch_backup_coreCA.sh"

# Path to the backup archive
BACKUP_ARCHIVE = "/home/backup_archive"



# Run the server backup script and log output
echo "Running server data backup: $SERVER_BACKUP_SCRIPT" | tee -a "$BACKUP_LOG"
bash "$SERVER_BACKUP_SCRIPT" 2>&1 | tee -a "$BACKUP_LOG"

# Check if the server backup script ran successfully
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "Server data backup completed successfully." | tee -a "$BACKUP_LOG"
else
    echo "Error: Server data backup failed to complete." | tee -a "$BACKUP_LOG"
    exit 1
fi

# Run the coreCA backup script and log output
echo "Running coreCA data backup: $CORECA_BACKUP_SCRIPT" | tee -a "$BACKUP_LOG"
bash "$CORECA_BACKUP_SCRIPT" 2>&1 | tee -a "$BACKUP_LOG"

# Check if the coreCA backup script ran successfully
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "CoreCA data backup completed successfully." | tee -a "$BACKUP_LOG"
else
    echo "Error: CoreCA data backup failed to complete." | tee -a "$BACKUP_LOG"
    exit 1
fi

echo "All backup processes completed at $(date)" | tee -a "$BACKUP_LOG"


rm -r encrypted_backup 
# Encrypting the synced archive
echo " Encrypting the archive "
gpgtar --encrypt  --output  encrypted_backup -r group10 backup_archive
if [ ${PIPESTATUS[0]} -eq 0 ];  then
    echo "Ecryption succesfull"  | tee -a "$BACKUP_LOG"
else 
    echo "Error: Encryption failed to complete." | tee -a "$BACKUP_LOG" 
    exit 1
fi


# Removing plain backup_data
rm -r backup_archive
