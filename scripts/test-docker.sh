#!/bin/bash
set -e

PYTHON_VERSIONS=("3.12" "3.13" "3.14")
NODE_VERSIONS=("20" "22" "23")

# Parse arguments
RUN_ALL=true
PYTHON_FILTER=""
NODE_FILTER=""
COMBO=""
PARALLEL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --python)
            PYTHON_FILTER="$2"
            RUN_ALL=false
            shift 2
            ;;
        --node)
            NODE_FILTER="$2"
            RUN_ALL=false
            shift 2
            ;;
        --combo)
            COMBO="$2"
            RUN_ALL=false
            shift 2
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --python VERSION  Test specific Python version (3.12, 3.13, 3.14)"
            echo "                    Runs all Node.js versions with that Python"
            echo "  --node VERSION    Test specific Node.js version (20, 22, 23)"
            echo "                    Runs all Python versions with that Node.js"
            echo "  --combo COMBO     Test specific combination (e.g., py313-node22)"
            echo "  --parallel        Run tests in parallel"
            echo "  --help            Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                          # Run all 9 combinations sequentially"
            echo "  $0 --parallel               # Run all 9 combinations in parallel"
            echo "  $0 --python 3.14            # Test Python 3.14 with Node 20, 22, 23"
            echo "  $0 --node 22                # Test Node 22 with Python 3.12, 3.13, 3.14"
            echo "  $0 --combo py313-node22     # Test specific combination"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
done

cd "$(dirname "$0")/.."

# Build service name from Python and Node versions
build_service_name() {
    local py_ver=$1
    local node_ver=$2
    echo "test-py${py_ver//./}-node${node_ver}"
}

# Run a single test combination
run_test() {
    local service=$1
    echo "=========================================="
    echo "Running: $service"
    echo "=========================================="
    docker compose -f docker-compose.test.yml build --no-cache "$service"
    docker compose -f docker-compose.test.yml run --rm "$service"
}

# Collect services to run
services_to_run=()

if [ -n "$COMBO" ]; then
    # Single combo specified
    services_to_run+=("test-$COMBO")
elif [ -n "$PYTHON_FILTER" ]; then
    # Filter by Python version
    for node_ver in "${NODE_VERSIONS[@]}"; do
        services_to_run+=("$(build_service_name "$PYTHON_FILTER" "$node_ver")")
    done
elif [ -n "$NODE_FILTER" ]; then
    # Filter by Node.js version
    for py_ver in "${PYTHON_VERSIONS[@]}"; do
        services_to_run+=("$(build_service_name "$py_ver" "$NODE_FILTER")")
    done
else
    # Run all combinations
    for py_ver in "${PYTHON_VERSIONS[@]}"; do
        for node_ver in "${NODE_VERSIONS[@]}"; do
            services_to_run+=("$(build_service_name "$py_ver" "$node_ver")")
        done
    done
fi

echo "Services to test: ${services_to_run[*]}"
echo ""

if [ "$PARALLEL" = true ]; then
    echo "Building and running tests in parallel..."
    # Build all services first
    for service in "${services_to_run[@]}"; do
        docker compose -f docker-compose.test.yml build --no-cache "$service" &
    done
    wait

    # Run all services
    docker compose -f docker-compose.test.yml up --abort-on-container-exit "${services_to_run[@]}"
else
    # Run sequentially
    for service in "${services_to_run[@]}"; do
        run_test "$service"
    done
fi

echo ""
echo "All tests passed!"
