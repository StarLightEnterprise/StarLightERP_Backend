#!/bin/bash

# Database connection parameters
DB_USER="starlighterp_api"
DB_NAME="starlighterp_db"
DB_PASSWORD="StarLightERP_API_01"
DB_HOST="localhost"

echo "=== Creating Customers and Customer_User Tables ==="
echo ""

# Execute customers table creation
echo "1. Creating customers table..."
PGPASSWORD=$DB_PASSWORD psql -U $DB_USER -h $DB_HOST -d $DB_NAME -f create_customers_table.sql
if [ $? -eq 0 ]; then
    echo "✓ Customers table created successfully"
else
    echo "✗ Failed to create customers table"
    exit 1
fi

echo ""

# Execute customer_user table creation
echo "2. Creating customer_user relationship table..."
PGPASSWORD=$DB_PASSWORD psql -U $DB_USER -h $DB_HOST -d $DB_NAME -f create_customer_user_table.sql
if [ $? -eq 0 ]; then
    echo "✓ Customer_user table created successfully"
else
    echo "✗ Failed to create customer_user table"
    exit 1
fi

echo ""
echo "=== Verifying Table Structures ==="
echo ""

# Verify customers table
echo "Customers table structure:"
PGPASSWORD=$DB_PASSWORD psql -U $DB_USER -h $DB_HOST -d $DB_NAME -c "\d customers"

echo ""
echo "Customer_user table structure:"
PGPASSWORD=$DB_PASSWORD psql -U $DB_USER -h $DB_HOST -d $DB_NAME -c "\d customer_user"

echo ""
echo "=== Migration completed successfully ==="
