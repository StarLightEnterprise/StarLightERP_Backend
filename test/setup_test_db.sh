#!/bin/bash
set -e

DB_NAME="starlighterp_db"
DB_USER="starlighterp_api"
export PGPASSWORD="StarLightERP_API_01"
# DB_HOST="localhost" # Assuming local socket or localhost

echo "Setting up Test Schema in database '$DB_NAME'..."

# Get the directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Execute SQL script
psql -h localhost -U $DB_USER -d $DB_NAME -f "$SCRIPT_DIR/setup_test_schema.sql"

echo "Test Schema Setup Complete."
