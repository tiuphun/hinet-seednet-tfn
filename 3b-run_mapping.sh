#!/bin/bash
# Taiwan ISP Topology Mapping - Master Control Script
# Usage: ./run_mapping.sh [command] [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DATA_DIR:-./traceroute_data}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    echo_info "Checking dependencies..."
    
    local missing_deps=()
    
    command -v python3 >/dev/null 2>&1 || missing_deps+=("python3")
    command -v traceroute >/dev/null 2>&1 || missing_deps+=("traceroute")
    command -v whois >/dev/null 2>&1 || missing_deps+=("whois")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo_error "Missing dependencies: ${missing_deps[*]}"
        echo_info "Install with: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    echo_info "All dependencies satisfied"
}

# Setup environment
setup_environment() {
    echo_info "Setting up environment..."
    
    # Create directory structure
    mkdir -p "$DATA_DIR"/{raw,analysis,exports}
    
    # Check for required Python scripts
    if [ ! -f "topology_mapping.py" ]; then
        echo_error "topology_mapping.py not found"
        exit 1
    fi
    
    if [ ! -f "topology_analysis.py" ]; then
        echo_error "topology_analysis.py not found"
        exit 1
    fi
    
    echo_info "Environment setup complete"
}

# Run collection from a specific vantage point
run_collection() {
    local vantage_point=$1
    local category=${2:-""}
    local protocols=${3:-"icmp tcp-80 tcp-443"}
    
    echo_info "Starting data collection..."
    echo_info "Vantage Point: $vantage_point"
    echo_info "Category: ${category:-ALL}"
    echo_info "Protocols: $protocols"
    
    local cmd="python3 topology_mapping.py \
        --vantage-point $vantage_point \
        --output-dir $DATA_DIR \
        --protocols $protocols \
        --delay 1.0"
    
    if [ -n "$category" ]; then
        cmd="$cmd --category $category"
    fi
    
    echo_info "Running: $cmd"
    eval $cmd
    
    echo_info "Collection complete!"
}

# Run analysis
run_analysis() {
    echo_info "Starting comprehensive analysis..."
    
    python3 topology_analysis.py "$DATA_DIR"
    
    echo_info "Analysis complete!"
}

# Run quick test collection
run_quick_test() {
    local vantage_point=$1
    
    echo_info "Running quick test collection (DNS resolvers only)..."
    
    python3 topology_mapping.py \
        --vantage-point "$vantage_point" \
        --category dns_resolvers \
        --output-dir "${DATA_DIR}_test" \
        --protocols icmp \
        --delay 0.5
    
    echo_info "Quick test complete!"
}

# Compare two vantage points
compare_vantage_points() {
    local vp1_dir=$1
    local vp2_dir=$2
    local output_file=${3:-"vantage_point_comparison.json"}
    
    echo_info "Comparing vantage points..."
    echo_info "VP1: $vp1_dir"
    echo_info "VP2: $vp2_dir"
    
    python3 topology_analysis.py compare "$vp1_dir" "$vp2_dir" "$output_file"
    
    echo_info "Comparison saved to $output_file"
}

# Show usage
show_usage() {
    cat << EOF
Taiwan ISP Topology Mapping - Control Script

USAGE:
    ./run_mapping.sh [command] [options]

COMMANDS:
    setup                           Setup environment and check dependencies
    
    collect <vantage-point>         Run full collection
                                    vantage-point: university|cht-mobile|itaiwan
    
    collect-category <vantage-point> <category>
                                    Run collection for specific category
    
    test <vantage-point>            Run quick test collection
    
    analyze                         Run comprehensive analysis on collected data
    
    compare <dir1> <dir2>           Compare two vantage point datasets
    
    full-cycle <vantage-point>      Run complete collection and analysis cycle
    
    help                            Show this help message

EXAMPLES:
    # Setup and test
    ./run_mapping.sh setup
    ./run_mapping.sh test university
    
    # Run full collection from university network
    ./run_mapping.sh collect university
    
    # Collect only government targets from CHT mobile
    ./run_mapping.sh collect-category cht-mobile government_central
    
    # Analyze collected data
    ./run_mapping.sh analyze
    
    # Full cycle: collect and analyze
    ./run_mapping.sh full-cycle university
    
    # Compare two vantage points
    ./run_mapping.sh compare ./data_university ./data_cht_mobile

ENVIRONMENT VARIABLES:
    DATA_DIR                        Output directory (default: ./traceroute_data)

EOF
}

# Full collection and analysis cycle
full_cycle() {
    local vantage_point=$1
    
    echo_info "Starting full collection and analysis cycle..."
    echo_info "This will take several hours to complete."
    
    # Collection
    run_collection "$vantage_point"
    
    # Analysis
    run_analysis
    
    echo_info "Full cycle complete!"
}

# Main command dispatcher
main() {
    local command=${1:-help}
    
    case $command in
        setup)
            check_dependencies
            setup_environment
            ;;
        
        collect)
            if [ -z "$2" ]; then
                echo_error "Vantage point required"
                show_usage
                exit 1
            fi
            check_dependencies
            setup_environment
            run_collection "$2"
            ;;
        
        collect-category)
            if [ -z "$2" ] || [ -z "$3" ]; then
                echo_error "Vantage point and category required"
                show_usage
                exit 1
            fi
            check_dependencies
            setup_environment
            run_collection "$2" "$3"
            ;;
        
        test)
            if [ -z "$2" ]; then
                echo_error "Vantage point required"
                show_usage
                exit 1
            fi
            check_dependencies
            run_quick_test "$2"
            ;;
        
        analyze)
            if [ ! -d "$DATA_DIR" ]; then
                echo_error "Data directory not found: $DATA_DIR"
                exit 1
            fi
            run_analysis
            ;;
        
        compare)
            if [ -z "$2" ] || [ -z "$3" ]; then
                echo_error "Two directories required for comparison"
                show_usage
                exit 1
            fi
            compare_vantage_points "$2" "$3" "${4:-vantage_point_comparison.json}"
            ;;
        
        full-cycle)
            if [ -z "$2" ]; then
                echo_error "Vantage point required"
                show_usage
                exit 1
            fi
            check_dependencies
            setup_environment
            full_cycle "$2"
            ;;
        
        help|--help|-h)
            show_usage
            ;;
        
        *)
            echo_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"