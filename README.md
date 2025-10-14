# Taiwan ISP Topology Mapping Research

Comprehensive automated traceroute system for mapping network topology of major Taiwan ISPs: HiNet (AS3462), SEEDnet (AS4780), and Taiwan Fixed Network (AS9924).

## 📋 Table of Contents

- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Data Collection Strategy](#data-collection-strategy)
- [Analysis Tools](#analysis-tools)
- [Output Files](#output-files)
- [Research Methodology](#research-methodology)

## 🎯 Overview

This toolkit provides:

1. **Automated Traceroute Collection** - Systematic collection from multiple vantage points
2. **Multi-Protocol Testing** - ICMP, TCP/80, TCP/443 for comprehensive path discovery
3. **Target Coverage** - 165+ targets across government, financial, educational, and critical infrastructure
4. **Advanced Analysis** - AS-level path analysis, peering detection, load balancing identification
5. **Visualization** - Graph generation for network topology visualization

## 💻 System Requirements

### Required Software

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3 python3-pip traceroute whois

# Alternative: Fedora/RHEL
sudo dnf install -y python3 python3-pip traceroute whois

# macOS
brew install python3 traceroute
```

### Python Dependencies

No external Python packages required - uses only standard library.

### Hardware Requirements

- **Storage**: 5-10 GB for full dataset
- **Memory**: 2 GB RAM minimum
- **Network**: Stable internet connection from vantage points

### Permissions

```bash
# Some systems require sudo for traceroute
# Test without sudo first, add if needed
traceroute google.com

# If permission denied:
sudo setcap cap_net_raw+ep $(which traceroute)
# OR run collection scripts with sudo
```

## 📦 Installation

```bash
# 1. Clone or download the scripts
mkdir taiwan_isp_topology
cd taiwan_isp_topology

# 2. Save the Python scripts:
#    - taiwan_topology_mapper.py (main collection script)
#    - topology_analysis.py (analysis script)
#    - run_mapping.sh (control script)

# 3. Make control script executable
chmod +x run_mapping.sh

# 4. Setup environment
./run_mapping.sh setup

# 5. Verify installation
./run_mapping.sh test university
```

## 🚀 Quick Start

### 1. Test Your Setup

```bash
# Quick test from university network
./run_mapping.sh test university

# This will trace to DNS resolvers only (fast test)
```

### 2. Run First Collection

```bash
# Collect from university vantage point
./run_mapping.sh collect university

# This will take 2-4 hours for full collection
```

### 3. Analyze Results

```bash
# Run comprehensive analysis
./run_mapping.sh analyze

# Results will be in traceroute_data/analysis_TIMESTAMP/
```

### 4. View Results

```bash
# Main report
cat traceroute_data/analysis_*/COMPREHENSIVE_REPORT.txt

# Generate topology visualization (requires Graphviz)
sudo apt-get install graphviz
dot -Tpng traceroute_data/analysis_*/topology.dot -o topology.png
```

## 📖 Detailed Usage

### Collection from Multiple Vantage Points

#### University Network (CCU Campus Network)

```bash
# Full collection - all categories, all protocols
./run_mapping.sh collect university

# Specific category only
./run_mapping.sh collect-category university government_central

# Custom output directory
DATA_DIR=./data_university ./run_mapping.sh collect university
```

#### Chunghwa Telecom Mobile (CHT SIM)

```bash
# Switch to mobile connection, then:
./run_mapping.sh collect cht-mobile

# Save to separate directory
DATA_DIR=./data_cht_mobile ./run_mapping.sh collect cht-mobile
```

#### iTaiwan WiFi (Library)

```bash
# Connect to iTaiwan, then:
./run_mapping.sh collect itaiwan

# Save to separate directory
DATA_DIR=./data_itaiwan ./run_mapping.sh collect itaiwan
```

### Advanced Collection Options

#### Using Python Script Directly

```bash
# More control over collection parameters
python3 taiwan_topology_mapper.py \
    --vantage-point university \
    --category financial_banks \
    --protocols icmp tcp-443 \
    --output-dir ./data_banks \
    --delay 2.0  # Slower, more polite

# IPv6 collection (if supported)
# Modify script or use external tool like traceroute6
```

#### Time-Based Collection

```bash
# Morning collection (8-10 AM)
./run_mapping.sh collect university > morning_$(date +%Y%m%d).log 2>&1

# Evening collection (8-10 PM)
./run_mapping.sh collect university > evening_$(date +%Y%m%d).log 2>&1

# Weekend collection
# Run on Saturday/Sunday to capture different routing
```

#### Staged Collection Strategy

```bash
# Day 1: Critical infrastructure
python3 taiwan_topology_mapper.py \
    --vantage-point university \
    --category government_critical

# Day 2: Financial sector
python3 taiwan_topology_mapper.py \
    --vantage-point university \
    --category financial_banks

# Day 3: Universities and education
python3 taiwan_topology_mapper.py \
    --vantage-point university \
    --category universities
```

## 📊 Data Collection Strategy

### Recommended Collection Schedule

```
Week 1: University Vantage Point
  Day 1-2: Government + Critical Infrastructure
  Day 3-4: Financial + Healthcare
  Day 5-6: E-commerce + Media
  Day 7: Analysis and verification

Week 2: CHT Mobile Vantage Point
  Repeat Week 1 targets from mobile network

Week 3: iTaiwan Vantage Point
  Repeat Week 1 targets from iTaiwan WiFi

Week 4: Comparative Analysis
  Compare all three vantage points
  Identify routing differences
  Generate final reports
```

### Multi-Protocol Strategy

Each target is traced using three protocols:

1. **ICMP** - Traditional traceroute, good for core routing
2. **TCP/80** - HTTP path, may differ due to CDN/load balancing
3. **TCP/443** - HTTPS path, captures SSL/security routing

### Time Diversity

Collect at different times to capture:
- **Peak hours** (12:00-14:00, 20:00-22:00): High traffic, potential alternate paths
- **Off-peak** (02:00-06:00): Baseline routing
- **Weekday vs Weekend**: Different traffic patterns

## 🔬 Analysis Tools

### 1. Core Router Identification

```bash
# Find routers appearing in many paths
python3 -c "
from topology_analysis import ComprehensiveAnalyzer
analyzer = ComprehensiveAnalyzer('traceroute_data')
analyzer.run_full_analysis()
"

# Output: traceroute_data/analysis_*/graph_statistics.json
# Look for 'top_hubs' section
```

### 2. AS-Level Path Analysis

```bash
# Analyze AS paths and peering
# Output: traceroute_data/analysis_*/as_paths.json
#         traceroute_data/analysis_*/peering_points.json

# View top peering relationships
cat traceroute_data/analysis_*/COMPREHENSIVE_REPORT.txt | grep -A 20 "TOP PEERING"
```

### 3. Load Balancing Detection

```bash
# Find targets with multiple paths
# Output: traceroute_data/analysis_*/load_balancing.json

# Quick view
jq '.[] | select(.unique_paths > 1) | {target, unique_paths}' \
   traceroute_data/analysis_*/load_balancing.json
```

### 4. ISP Infrastructure Mapping

```bash
# Identify which ISP routers are used
# Output: traceroute_data/analysis_*/isp_analysis.json

# Summary by ISP
jq 'to_entries | .[] | {isp: .key, routers: .value.unique_routers}' \
   traceroute_data/analysis_*/isp_analysis.json
```

### 5. Vantage Point Comparison

```bash
# Compare university vs CHT mobile
./run_mapping.sh compare \
    ./data_university \
    ./data_cht_mobile \
    comparison_uni_vs_cht.json

# View differences
jq '.different_paths[] | {target, similarity}' comparison_uni_vs_cht.json
```

### 6. Graph Visualization

```bash
# Generate network topology graph
cd traceroute_data/analysis_*/

# Simple visualization
dot -Tpng topology.dot -o topology.png

# Large graph (hierarchical layout)
dot -Tpng -Grankdir=TB topology.dot -o topology_vertical.png

# For very large graphs
sfdp -Tpng topology.dot -o topology_force.png

# Import into Gephi for interactive visualization
# Use topology_nodes.csv and topology_edges.csv
```

## 📁 Output Files

### Directory Structure

```
traceroute_data/
├── raw/                                    # Individual traceroute JSON files
│   ├── 20241014_100530_ntu.edu.tw_icmp.json
│   ├── 20241014_100545_cht.com.tw_tcp.json
│   └── ...
├── summary_20241014_100000.json           # Collection summary
├── traceroutes_20241014_100000.csv        # CSV export for analysis
├── collection_20241014_100000.log         # Collection log
└── analysis_20241014_150000/              # Analysis results
    ├── COMPREHENSIVE_REPORT.txt           # Main human-readable report
    ├── as_paths.json                      # AS-level paths
    ├── as_borders.json                    # AS border crossings
    ├── peering_points.json                # Peering relationships
    ├── load_balancing.json                # Multiple paths detected
    ├── latency_stats.json                 # Hop-by-hop latency
    ├── graph_statistics.json              # Network graph metrics
    ├── isp_analysis.json                  # ISP infrastructure usage
    ├── topology.dot                       # Graphviz format
    ├── topology_nodes.csv                 # Gephi import (nodes)
    └── topology_edges.csv                 # Gephi import (edges)
```

### Key Output Files

#### 1. COMPREHENSIVE_REPORT.txt
Human-readable summary with:
- Top peering relationships
- Core hub routers
- ISP infrastructure usage
- Load balancing summary
- Latency statistics

#### 2. as_paths.json
AS-level paths for each traceroute:
```json
{
  "target": "ntu.edu.tw",
  "as_path": [
    {"asn": "3462", "ip": "168.95.1.1", "description": "HINET"},
    {"asn": "9924", "ip": "163.28.1.1", "description": "TWAREN"}
  ]
}
```

#### 3. peering_points.json
Identified peering relationships:
```json
{
  "from_asn": "3462",
  "to_asn": "9924",
  "occurrences": 45,
  "unique_targets": 23
}
```

#### 4. graph_statistics.json
Network topology metrics:
```json
{
  "total_nodes": 1245,
  "total_edges": 3456,
  "top_hubs": [
    {
      "ip": "168.95.1.1",
      "total_degree": 234,
      "in_degree": 120,
      "out_degree": 114
    }
  ]
}
```

## 🔍 Research Methodology

### Target Selection Rationale

**Government Targets**: Critical for understanding national infrastructure routing and redundancy.

**Financial Institutions**: High-security requirements, likely multi-homed with diverse paths.

**Universities**: Connected via TWAREN, shows research/education network peering.

**E-commerce/Tech**: High traffic, may use CDNs and load balancing extensively.

**Healthcare**: Critical infrastructure with specific reliability requirements.

**DNS Resolvers**: Direct ISP infrastructure, shows internal routing.

### Vantage Point Strategy

1. **University Network (CCU)**
   - Likely connects via TWAREN
   - Academic peering arrangements
   - May have direct connections to research networks

2. **CHT Mobile (SIM Card)**
   - Consumer mobile network
   - May route differently than fixed-line
   - Shows mobile infrastructure separation

3. **iTaiwan WiFi**
   - Municipal network
   - Varies by location (library-specific routing)
   - May use local ISP as upstream

### Multi-Protocol Testing

Different protocols may reveal:
- **ICMP**: Core IP routing, may be rate-limited
- **TCP/80**: Web traffic path, CDN selection
- **TCP/443**: Encrypted traffic, may differ for security policies

### Ethical Considerations

✅ **Acceptable**:
- Standard traceroute to public services
- Reasonable rate limiting (1+ second delays)
- Collecting routing information only

❌ **Avoid**:
- Excessive requests (DDoS-like behavior)
- Attempting to bypass security
- Probing non-public infrastructure

### Data Privacy

- No user data collected
- Only network routing information
- IP addresses are public infrastructure
- Aggregated analysis only

## 🔧 Troubleshooting

### Common Issues

**1. Permission Denied**
```bash
# Solution: Add capabilities or use sudo
sudo setcap cap_net_raw+ep $(which traceroute)
# OR
sudo python3 taiwan_topology_mapper.py --vantage-point university
```

**2. DNS Resolution Failures**
```bash
# Some targets may be temporarily down
# Check logs: traceroute_data/collection_*.log
# Script continues with other targets
```

**3. Traceroute Timeouts**
```bash
# Increase timeout or skip problematic targets
# Edit taiwan_topology_mapper.py:
# timeout=120 -> timeout=180
```

**4. Rate Limiting**
```bash
# Increase delay between traceroutes
python3 taiwan_topology_mapper.py \
    --vantage-point university \
    --delay 2.0  # or higher
```

**5. ASN Lookup Failures**
```bash
# Whois service may be rate-limited
# ASN lookups are cached in asn_cache.json
# Can manually populate cache or wait and retry
```

### Performance Optimization

```bash
# For faster collection (use responsibly):
python3 taiwan_topology_mapper.py \
    --vantage-point university \
    --delay 0.5  # Faster but more aggressive

# For very large datasets:
# Run collections in parallel for different categories
python3 taiwan_topology_mapper.py --category government_central &
python3 taiwan_topology_mapper.py --category financial_banks &
wait
```

## 📈 Expected Results

### Typical Collection Times

- **Single target (3 protocols)**: ~10-15 seconds
- **Single category (10-15 targets)**: ~5-10 minutes
- **Full collection (165 targets)**: ~2-4 hours
- **All three vantage points**: ~6-12 hours total

### Dataset Sizes

- **Raw JSON files**: ~50-100 KB per traceroute
- **Full collection**: ~50-100 MB
- **All vantage points**: ~150-300 MB
- **With analysis**: ~500 MB - 1 GB

### Key Findings to Look For

1. **Core Transit Routers**: High-degree nodes in graph
2. **AS Peering Relationships**: HiNet-TWAREN, SEEDnet-HiNet, etc.
3. **Geographic Routing**: North-South paths, submarine cables
4. **Load Balancing**: Multiple paths to major services
5. **ISP Market Share**: Router appearance frequency
6. **Critical Chokepoints**: Single routers all paths traverse

## 📚 Further Reading

- **TWAREN Network**: Taiwan Advanced Research and Education Network
- **BGP Routing**: Border Gateway Protocol path selection
- **Internet Exchange Points**: TPIX, TWIX infrastructure
- **Traceroute Analysis**: Paris traceroute, multipath detection

## 🤝 Contributing

For research collaboration or questions:
- Document your methodology
- Share interesting findings
- Contribute target lists
- Report bugs or improvements

## ⚖️ License and Usage

This toolkit is for academic research purposes. Users are responsible for:
- Complying with network acceptable use policies
- Respecting rate limits and service terms
- Using data ethically and responsibly
- Proper attribution in publications

---

**Last Updated**: October 2024
**Version**: 1.0
**Contact**: National Chung Cheng University Network Research Lab