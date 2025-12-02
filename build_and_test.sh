#!/bin/bash
set -e

# Configuration
BUILD_DIR="build"
TEST_DIR="test"

# Ensure we are in the script's directory
cd "$(dirname "$0")"

echo "Starting Backend Build and Test Process..."

# 1. Clean previous build (optional, maybe flag based)
# rm -rf $BUILD_DIR

# 2. Configure CMake
if [ ! -d "$BUILD_DIR" ]; then
    mkdir $BUILD_DIR
fi

cd $BUILD_DIR
cmake ..
cd ..

# 3. Build Backend
echo "Building Backend..."
cmake --build $BUILD_DIR -- -j$(nproc)

# 4. Build Tests
echo "Building Tests..."
# Assuming tests are part of the main build or separate
# In our CMakeLists.txt, we added test subdirectory
# So they should be built.

# 5. Run Tests
# 5. Run Tests
echo "Running Backend Tests..."
cd $BUILD_DIR/test

# Generate config.json from test_config.env
# We need to go up to root to find test_config.env
if [ -f "../../test_config.env" ]; then
    set -a
    source ../../test_config.env
    set +a
    
    # Create a temporary config.json for testing
    cat <<EOF > config.json
{
    "app": {
        "log": {
            "log_level": "DEBUG"
        },
        "run_as_daemon": false
    },
    "db_clients": [
        {
            "name": "default",
            "rdbms": "postgresql",
            "host": "$DB_HOST",
            "port": $DB_PORT,
            "dbname": "$DB_NAME",
            "user": "$DB_USER",
            "password": "$PGPASSWORD",
            "is_fast": false,
            "client_encoding": "UTF8",
            "connection_number": 1
        }
    ]
}
EOF
fi

./StarLightERP_Backend_Temp_test

echo "Backend Build and Test Successful!"
