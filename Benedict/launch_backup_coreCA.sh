
#!/bin/bash

# Function to perform mount, backup, and unmount
perform_backup () {
    local mount_point=$1
    local remote_dest=$2
    local backup_dest=$3

    # Check and create mount_point if it doesn't exist
    if [ ! -d "$mount_point" ]; then
        echo "Mount point $mount_point does not exist, creating it..."
        mkdir -p "$mount_point"
    fi

    # Check and create backup_dest if it doesn't exist
    if [ ! -d "$backup_dest" ]; then
        echo "Backup destination $backup_dest does not exist, creating it..."
        mkdir -p "$backup_dest"
    fi

    # Mount the remote directory we want to back up
    echo "Mounting $remote_dest from $REMOTE_HOST to $mount_point..."
    if sshfs $REMOTE_HOST:$remote_dest $mount_point; then
        echo "Mount successful."
    else
        echo "Error: Failed to mount $remote_dest. Exiting."
        exit 1
    fi

    # Perform the backup
    echo "Starting backup from $mount_point to $backup_dest..."
    if rsync -avz --delete $mount_point/ $backup_dest; then
        echo "Backup completed successfully."
    else
        echo "Error: Backup failed. Exiting."
        exit 1
    fi

    # Unmount the remote directory
    echo "Unmounting $mount_point..."
    if fusermount -u $mount_point; then
        echo "Unmount successful."
    else
        echo "Error: Failed to unmount $mount_point."
        exit 1
    fi
}

# Variables
MOUNT_POINT="/mnt/core_archive_1"
MOUNT_POINT_2="/mnt/core_archive_2"
MOUNT_POINT_3="/mnt/core_archive_3"

REMOTE_DEST="/home/server/core1"
REMOTE_DEST_2="/home/server/core2"
REMOTE_DEST_3="/home/server/core3"

BACKUP_DEST="/home/backup_archive/core_archive/var/www/auth_manger/"
BACKUP_DEST_2="/home/backup_archive/core_archive/etc/apache2/"
BACKUP_DEST_3="/home/backup_archive/core_archive/var/lib/mysql/imovies"

REMOTE_HOST="root@10.0.2.7"

# Perform the first backup
perform_backup $MOUNT_POINT $REMOTE_DEST $BACKUP_DEST

# Perform the second backup
perform_backup $MOUNT_POINT_2 $REMOTE_DEST_2 $BACKUP_DEST_2

# Perform the third backup
perform_backup $MOUNT_POINT_3 $REMOTE_DEST_3 $BACKUP_DEST_3

echo "Backup process finished."
