#!/bin/bash

# Database reset helper script
# Reads config file and drops/creates the test database

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <config-file>"
    exit 1
fi

CONFIG_FILE="$1"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    exit 1
fi

# Source the config file
source "$CONFIG_FILE"

# Determine database type
if [ -z "$SYS_DB_TYPE" ]; then
    echo "Error: SYS_DB_TYPE not found in config file"
    exit 1
fi

echo "Database type: $SYS_DB_TYPE"

# Reset database based on type
case "$SYS_DB_TYPE" in
    postgres)
        PGHOST="${POSTGRES_HOST:-localhost}"
        PGPORT="${POSTGRES_PORT:-5432}"
        PGUSER="${POSTGRES_USER:-postgres}"
        PGDATABASE="${POSTGRES_DBNAME:-slauth_test}"
        PGPASSWORD="${POSTGRES_PASSWORD}"
        
        echo "Dropping PostgreSQL database: $PGDATABASE"
        PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "DROP DATABASE IF EXISTS $PGDATABASE;" 2>&1 | grep -v "does not exist" || true
        
        echo "Creating PostgreSQL database: $PGDATABASE"
        PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d postgres -c "CREATE DATABASE $PGDATABASE;"
        
        echo "PostgreSQL database reset completed: $PGDATABASE"
        ;;
        
    mysql)
        MYSQL_HOST="${SYS_DB_HOST:-127.0.0.1}"
        MYSQL_PORT="${SYS_DB_PORT:-3306}"
        MYSQL_USER="${SYS_DB_USER:-root}"
        MYSQL_PASSWORD="${SYS_DB_PASSWORD}"
        MYSQL_DATABASE="${SYS_DB_DBNAME:-slauth_test}"
        
        echo "Dropping MySQL database: $MYSQL_DATABASE"
        mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "DROP DATABASE IF EXISTS $MYSQL_DATABASE;" 2>/dev/null || true
        
        echo "Creating MySQL database: $MYSQL_DATABASE"
        mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "CREATE DATABASE $MYSQL_DATABASE;"
        
        echo "MySQL database reset completed: $MYSQL_DATABASE"
        ;;
        
    sqlite|"")
        echo "SQLite uses in-memory database, no reset needed"
        ;;
        
    *)
        echo "Error: Unsupported database type: $SYS_DB_TYPE"
        exit 1
        ;;
esac

echo "Database reset successful!"

