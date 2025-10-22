#!/usr/bin/env python3
"""
Taiwan ISP Topology Mapping - Enhanced Traceroute Collection System
Research: HiNet (AS3462), SEEDnet (AS4780), Taiwan Fixed Network (AS9924)

Enhanced Features:
- Tests multiple service variants per domain (www, mail, ftp, etc.)
- Tests common service ports (HTTP, HTTPS, SMTP, DNS, etc.)
- Network discovery and ISP path identification
- Improved success rate through service discovery
"""

import subprocess
import json
import csv
import time
import socket
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set
import argparse
import logging
from collections import defaultdict

class NetworkDiscovery:
    """Network discovery and router categorization"""
    
    def __init__(self):
        # Network patterns for ISP identification
        self.network_patterns = {
            'hinet': {
                'patterns': [
                    r'.*\.hinet\.net',
                    r'.*\.hinet-ip\.hinet\.net',
                    r'.*-hinet\.net',
                ],
                'name': 'HiNet (Chunghwa Telecom)',
                'as_numbers': ['AS3462', 'AS9919']
            },
            'twaren': {
                'patterns': [
                    r'.*\.twaren\.net',
                    r'.*\.tw-nren\.net',
                ],
                'name': 'TWaren (Taiwan Advanced Research & Education Network)',
                'as_numbers': ['AS7539']
            },
            'tanet': {
                'patterns': [
                    r'.*\.tanet\.edu\.tw',
                ],
                'name': 'TANet (Taiwan Academic Network)',
                'as_numbers': []
            },
            'seednet': {
                'patterns': [
                    r'.*\.seed\.net\.tw',
                    r'.*\.seednet\.net',
                ],
                'name': 'SEEDNet',
                'as_numbers': ['AS4780']
            },
            'fetnet': {
                'patterns': [
                    r'.*\.fetnet\.net',
                    r'.*\.fareastone\.net\.tw',
                ],
                'name': 'FETNet (Far EasTone)',
                'as_numbers': ['AS9924']
            },
            'taiwanmobile': {
                'patterns': [
                    r'.*\.taiwanmobile\.com',
                    r'.*\.tmn\.net\.tw',
                ],
                'name': 'Taiwan Mobile',
                'as_numbers': ['AS24158']
            },
            'aptg': {
                'patterns': [
                    r'.*\.aptg\.com\.tw',
                    r'.*\.apol\.com\.tw',
                ],
                'name': 'Asia Pacific Telecom',
                'as_numbers': ['AS17415']
            },
            'sonet': {
                'patterns': [
                    r'.*\.so-net\.net\.tw',
                    r'.*\.so-net\.tw',
                ],
                'name': 'So-net Taiwan',
                'as_numbers': ['AS23899']
            },
            'chief': {
                'patterns': [
                    r'.*\.chief\.net\.tw',
                ],
                'name': 'Chief Telecom',
                'as_numbers': ['AS131584']
            },
            'university': {
                'patterns': [
                    r'.*\.edu\.tw',
                    r'.*\.ac\.tw',
                ],
                'name': 'Taiwan Universities',
                'as_numbers': []
            },
            'government': {
                'patterns': [
                    r'.*\.gov\.tw',
                ],
                'name': 'Taiwan Government',
                'as_numbers': []
            }
        }
        
        # Private/reserved IP ranges
        self.private_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^169\.254\.',
        ]
    
    def categorize_router(self, hostname: str, ip: str) -> Dict[str, any]:
        """Categorize router based on hostname and IP patterns"""
        result = {
            'network': 'unknown',
            'network_name': 'Unknown Network',
            'is_private': self.is_private_ip(ip),
            'is_interesting': False,
            'as_numbers': []
        }
        
        if not hostname:
            if result['is_private']:
                result['network'] = 'private'
                result['network_name'] = 'Private Network'
            return result
        
        hostname_lower = hostname.lower()
        
        # Check against all network patterns
        for network_key, network_info in self.network_patterns.items():
            for pattern in network_info['patterns']:
                if re.match(pattern, hostname_lower):
                    result['network'] = network_key
                    result['network_name'] = network_info['name']
                    result['as_numbers'] = network_info.get('as_numbers', [])
                    result['is_interesting'] = True
                    return result
        
        # If no pattern matched but has a hostname
        result['network'] = 'other'
        result['network_name'] = 'Other Network'
        return result
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        for pattern in self.private_ranges:
            if re.match(pattern, ip):
                return True
        return False
    
    def analyze_path(self, hops: List[Dict]) -> Dict[str, any]:
        """Analyze the network path through different ISPs/networks"""
        path_analysis = {
            'networks_traversed': [],
            'interesting_routers': [],
            'private_hops': 0,
            'total_hops': len(hops),
            'network_transitions': []
        }
        
        previous_network = None
        networks_seen = set()
        
        for hop in hops:
            if not hop.get('ip') or hop.get('timeout'):
                continue
            
            # Get router categorization
            categorization = self.categorize_router(
                hop.get('hostname'),
                hop['ip']
            )
            
            # Add to hop data
            hop['network'] = categorization['network']
            hop['network_name'] = categorization['network_name']
            hop['is_interesting'] = categorization['is_interesting']
            hop['is_private'] = categorization['is_private']
            
            # Track network transitions
            current_network = categorization['network']
            if current_network != previous_network and previous_network is not None:
                path_analysis['network_transitions'].append({
                    'hop': hop['hop'],
                    'from': previous_network,
                    'to': current_network,
                    'from_ip': hops[hop['hop']-2]['ip'] if hop['hop'] > 1 else None,
                    'to_ip': hop['ip']
                })
            
            # Track networks traversed
            if current_network not in networks_seen:
                networks_seen.add(current_network)
                path_analysis['networks_traversed'].append({
                    'network': current_network,
                    'network_name': categorization['network_name'],
                    'first_hop': hop['hop']
                })
            
            # Track interesting routers
            if categorization['is_interesting']:
                path_analysis['interesting_routers'].append({
                    'hop': hop['hop'],
                    'ip': hop['ip'],
                    'hostname': hop.get('hostname'),
                    'network': current_network,
                    'network_name': categorization['network_name']
                })
            
            # Count private hops
            if categorization['is_private']:
                path_analysis['private_hops'] += 1
            
            previous_network = current_network
        
        return path_analysis


class TracerouteCollector:
    def __init__(self, output_dir: str = "traceroute_data", vantage_point: str = "unknown"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.vantage_point = vantage_point
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Initialize network discovery
        self.network_discovery = NetworkDiscovery()
        
        # Setup logging
        log_file = self.output_dir / f"collection_{self.timestamp}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Target categories
        self.targets = self._load_targets()
        
        # Service variants to test for each domain
        self.service_prefixes = [
            "",          # bare domain
            "www",       # web service
            "www2",      # alternate web
            "mail",      # mail service
            "smtp",      # SMTP server
            "ftp",       # FTP service
            "ns",        # nameserver
            "ns1",       # primary nameserver
            "ns2",       # secondary nameserver
            "api",       # API endpoint
            "app",       # application
            "portal",    # portal
            "webmail",   # webmail
            "vpn",       # VPN gateway
            "remote",    # remote access
        ]
        
        # Common service ports to test
        self.service_ports = {
            "http": 80,
            "https": 443,
            "smtp": 25,
            "smtp-alt": 587,
            "smtps": 465,
            "dns": 53,
            "ftp": 21,
            "ssh": 22,
            "rdp": 3389,
            "mysql": 3306,
            "postgres": 5432,
        }
        
    def _load_targets(self) -> Dict[str, List[str]]:
        """Load all targets organized by category"""
        return {
            "government_central": [
                "president.gov.tw", "ey.gov.tw", "mofa.gov.tw", "moi.gov.tw",
                "mof.gov.tw", "moj.gov.tw", "mnd.gov.tw", "moea.gov.tw",
                "motc.gov.tw", "moe.gov.tw", "mohw.gov.tw", "ncc.gov.tw"
            ],
            "government_local": [
                "gov.taipei", "kcg.gov.tw", "taichung.gov.tw", "tainan.gov.tw",
                "ntpc.gov.tw", "taoyuan.gov.tw", "hccg.gov.tw", "chcg.gov.tw"
            ],
            "government_critical": [
                "npa.gov.tw", "nfa.gov.tw", "immigration.gov.tw", "judicial.gov.tw",
                "cib.gov.tw", "hpa.gov.tw", "cdc.gov.tw", "cwb.gov.tw"
            ],
            "universities": [
                "ntu.edu.tw", "nthu.edu.tw", "nctu.edu.tw", "ncu.edu.tw",
                "nchu.edu.tw", "ncku.edu.tw", "nsysu.edu.tw", "ccu.edu.tw",
                "ntnu.edu.tw", "nuk.edu.tw", "tku.edu.tw", "fcu.edu.tw",
                "cycu.edu.tw", "tmu.edu.tw", "nccu.edu.tw"
            ],
            "financial_banks": [
                "bot.com.tw", "megabank.com.tw", "landbank.com.tw", "tcb-bank.com.tw",
                "firstbank.com.tw", "huananbank.com.tw", "changhwabank.com.tw",
                "ctbcbank.com", "cathaybk.com.tw", "fubon.com", "esunbank.com.tw",
                "taishinbank.com.tw", "sinopac.com", "skbank.com.tw", "yuanta.com"
            ],
            "financial_infra": [
                "twse.com.tw", "tpex.org.tw", "tdcc.com.tw", "fisc.com.tw"
            ],
            "ecommerce_tech": [
                "pchome.com.tw", "24h.pchome.com.tw", "momoshop.com.tw",
                "shopee.tw", "ruten.com.tw", "books.com.tw", "104.com.tw",
                "1111.com.tw", "yes123.com.tw", "591.com.tw", "mobile01.com",
                "ptt.cc", "dcard.tw", "bahamut.com.tw", "gamer.com.tw"
            ],
            "media": [
                "ltn.com.tw", "udn.com", "chinatimes.com", "tvbs.com.tw",
                "settv.com.tw", "cts.com.tw", "ftv.com.tw", "pts.org.tw",
                "cna.com.tw", "storm.mg", "thenewslens.com"
            ],
            "telecom": [
                "cht.com.tw", "fetnet.net", "taiwanmobile.com", "aptg.com.tw",
                "tstar.com.tw", "chief.com.tw", "so-net.net.tw", "seednet.net"
            ],
            "healthcare": [
                "ntuh.gov.tw", "vghtpe.gov.tw", "mmh.org.tw", "cgmh.org.tw",
                "kmuh.org.tw", "nckuh.org.tw", "vghks.gov.tw", "tch.org.tw",
                "vghtc.gov.tw", "chimei.org.tw"
            ],
            "critical_infra": [
                "taipower.com.tw", "cpc.com.tw", "thsrc.com.tw",
                "railway.gov.tw", "metro.taipei", "krtco.com.tw",
                "taoyuan-airport.com"
            ],
            "cdn_global": [
                "google.com.tw", "facebook.com", "youtube.com", "netflix.com",
                "yahoo.com.tw", "microsoft.com", "apple.com", "cloudflare.com"
            ],
            "dns_resolvers": [
                "168.95.1.1", "168.95.192.1", "139.175.10.20",
                "139.175.150.20", "203.133.1.8", "210.241.0.4"
            ],
            "education_network": [
                "twaren.net", "tanet.edu.tw", "nchc.org.tw", "sinica.edu.tw"
            ]
        }
    
    def generate_service_variants(self, domain: str) -> List[str]:
        """Generate all service variants for a domain"""
        if self._is_ip(domain):
            return [domain]
        
        variants = []
        
        # Add bare domain
        variants.append(domain)
        
        # Add prefixed variants
        for prefix in self.service_prefixes:
            if prefix:  # Skip empty prefix (already added as bare domain)
                variant = f"{prefix}.{domain}"
                variants.append(variant)
        
        return variants
    
    def discover_reachable_services(self, domain: str, 
                                   quick_check: bool = True) -> List[Dict[str, any]]:
        """
        Discover which service variants and ports are reachable for a domain
        Returns list of reachable services with their details
        """
        reachable = []
        variants = self.generate_service_variants(domain)
        
        # Test each variant
        for variant in variants:
            ip = self.resolve_target(variant)
            if ip:
                service_info = {
                    "variant": variant,
                    "ip": ip,
                    "is_bare_domain": variant == domain,
                    "reachable": True
                }
                reachable.append(service_info)
                
                # If quick check and we found the bare domain, add www variant if different
                if quick_check and variant == domain:
                    www_variant = f"www.{domain}"
                    www_ip = self.resolve_target(www_variant)
                    if www_ip and www_ip != ip:
                        reachable.append({
                            "variant": www_variant,
                            "ip": www_ip,
                            "is_bare_domain": False,
                            "reachable": True
                        })
                    break  # Quick check only tests bare + www
        
        if not reachable:
            self.logger.warning(f"No reachable services found for {domain}")
        else:
            self.logger.info(f"Found {len(reachable)} reachable service(s) for {domain}")
        
        return reachable
    
    def resolve_target(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(target)
            self.logger.debug(f"Resolved {target} -> {ip}")
            return ip
        except socket.gaierror:
            self.logger.debug(f"Failed to resolve {target}")
            return None
    
    def run_traceroute(self, target: str, protocol: str = "icmp", 
                       port: int = 80, max_hops: int = 30,
                       metadata: Dict = None) -> Optional[Dict]:
        """Run a single traceroute with specified protocol"""
        
        # Resolve target
        ip = self.resolve_target(target) if not self._is_ip(target) else target
        if not ip:
            return None
        
        # Build traceroute command (with hostname resolution)
        cmd = self._build_traceroute_cmd(ip, protocol, port, max_hops, resolve_hostnames=True)
        
        self.logger.info(f"Running: {' '.join(cmd)}")
        
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            duration = time.time() - start_time
            
            # Parse output
            hops = self._parse_traceroute_output(result.stdout)
            
            # Analyze network path
            path_analysis = self.network_discovery.analyze_path(hops)
            
            trace_result = {
                "timestamp": datetime.now().isoformat(),
                "vantage_point": self.vantage_point,
                "target": target,
                "target_ip": ip,
                "protocol": protocol,
                "port": port if protocol in ["tcp", "udp"] else None,
                "duration_seconds": round(duration, 2),
                "hops": hops,
                "num_hops": len(hops),
                "success": any(h.get("ip") == ip for h in hops),
                "path_analysis": path_analysis,
                "raw_output": result.stdout
            }
            
            # Add metadata if provided
            if metadata:
                trace_result.update(metadata)
            
            return trace_result
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Traceroute to {target} timed out")
            return None
        except Exception as e:
            self.logger.error(f"Error running traceroute to {target}: {e}")
            return None
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, target))
    
    def _build_traceroute_cmd(self, ip: str, protocol: str, 
                             port: int, max_hops: int, resolve_hostnames: bool = True) -> List[str]:
        """Build traceroute command based on protocol"""
        # Base command - remove -n flag to get hostnames
        if resolve_hostnames:
            base_cmd = ["traceroute", "-w", "3", "-q", "3", "-m", str(max_hops)]
        else:
            base_cmd = ["traceroute", "-n", "-w", "3", "-q", "3", "-m", str(max_hops)]
        
        if protocol == "icmp":
            cmd = base_cmd + ["-I", ip]
        elif protocol == "udp":
            cmd = base_cmd + ["-p", str(port), ip]
        elif protocol == "tcp":
            cmd = base_cmd + ["-T", "-p", str(port), ip]
        else:
            cmd = base_cmd + [ip]
        
        return cmd
    
    def _parse_traceroute_output(self, output: str) -> List[Dict]:
        """Parse traceroute output into structured format"""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip first line (header)
            hop = self._parse_hop_line(line)
            if hop:
                hops.append(hop)
        
        return hops
    
    def _parse_hop_line(self, line: str) -> Optional[Dict]:
        """Parse a single hop line from traceroute output"""
        parts = line.strip().split()
        if not parts:
            return None
        
        try:
            hop_num = int(parts[0])
            
            if '*' in parts[1]:
                return {
                    "hop": hop_num,
                    "ip": None,
                    "hostname": None,
                    "rtts": [],
                    "timeout": True
                }
            
            # Check if we have hostname (hostname (IP)) or just IP
            hostname = None
            ip = None
            
            if '(' in line and ')' in line:
                # Has hostname: "hostname (IP)"
                match = re.search(r'([^\s\(]+)\s+\(([^\)]+)\)', line)
                if match:
                    hostname = match.group(1)
                    ip = match.group(2)
            else:
                # Just IP
                ip = parts[1]
            
            rtts = []
            
            # Extract RTT values
            for part in parts[2:]:
                if part == 'ms':
                    continue
                try:
                    rtt = float(part)
                    rtts.append(rtt)
                except ValueError:
                    pass
            
            return {
                "hop": hop_num,
                "ip": ip,
                "hostname": hostname,
                "rtts": rtts,
                "avg_rtt": round(sum(rtts) / len(rtts), 2) if rtts else None,
                "timeout": False
            }
            
        except (ValueError, IndexError):
            return None
    
    def collect_batch(self, category: str = None, protocols: List[str] = None,
                     delay: float = 1.0, service_discovery: bool = True,
                     max_services_per_domain: int = 3) -> List[Dict]:
        """
        Collect traceroutes for a batch of targets
        
        Args:
            category: Specific category to trace
            protocols: List of protocols to use
            delay: Delay between traceroutes
            service_discovery: Whether to discover and test service variants
            max_services_per_domain: Maximum number of service variants to test per domain
        """
        
        if protocols is None:
            protocols = ["icmp", "tcp-80", "tcp-443"]
        
        results = []
        tested_ips = set()  # Track IPs we've already tested
        
        # Select targets
        if category and category in self.targets:
            targets_dict = {category: self.targets[category]}
        else:
            targets_dict = self.targets
        
        total_domains = sum(len(targets) for targets in targets_dict.values())
        current_domain = 0
        
        for cat, targets in targets_dict.items():
            self.logger.info(f"Processing category: {cat}")
            
            for domain in targets:
                current_domain += 1
                self.logger.info(f"Progress: {current_domain}/{total_domains} - {domain}")
                
                # Discover reachable services for this domain
                if service_discovery and not self._is_ip(domain):
                    services = self.discover_reachable_services(
                        domain, 
                        quick_check=(max_services_per_domain <= 2)
                    )
                    
                    # Limit number of services to test
                    services = services[:max_services_per_domain]
                else:
                    # Just test the domain/IP itself
                    ip = self.resolve_target(domain) if not self._is_ip(domain) else domain
                    if ip:
                        services = [{
                            "variant": domain,
                            "ip": ip,
                            "is_bare_domain": True,
                            "reachable": True
                        }]
                    else:
                        services = []
                
                # Test each reachable service with each protocol
                for service in services:
                    target = service["variant"]
                    target_ip = service["ip"]
                    
                    for protocol_spec in protocols:
                        # Parse protocol specification
                        if '-' in protocol_spec:
                            protocol, port = protocol_spec.split('-')
                            port = int(port)
                        else:
                            protocol = protocol_spec
                            port = 80
                        
                        # Create unique key for this test
                        test_key = f"{target_ip}:{protocol}:{port}"
                        
                        # Skip if we've already tested this IP with this protocol/port
                        if test_key in tested_ips:
                            self.logger.debug(f"Skipping duplicate: {test_key}")
                            continue
                        
                        tested_ips.add(test_key)
                        
                        # Add metadata about the service
                        metadata = {
                            "category": cat,
                            "base_domain": domain,
                            "service_variant": target,
                            "is_bare_domain": service.get("is_bare_domain", False),
                        }
                        
                        result = self.run_traceroute(
                            target, protocol, port, metadata=metadata
                        )
                        
                        if result:
                            results.append(result)
                            self._save_result(result)
                        
                        time.sleep(delay)
        
        return results
    
    def _save_result(self, result: Dict):
        """Save individual result to JSON file"""
        timestamp = result["timestamp"].replace(':', '-').replace('.', '-')
        filename = f"{timestamp}_{result['target']}_{result['protocol']}.json"
        filepath = self.output_dir / "raw" / filename
        filepath.parent.mkdir(exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(result, f, indent=2)
    
    def save_summary(self, results: List[Dict]):
        """Save summary of all results"""
        summary_file = self.output_dir / f"summary_{self.timestamp}.json"
        
        summary = {
            "collection_timestamp": self.timestamp,
            "vantage_point": self.vantage_point,
            "total_traceroutes": len(results),
            "successful": sum(1 for r in results if r.get("success")),
            "failed": sum(1 for r in results if not r.get("success")),
            "categories": defaultdict(int),
            "protocols": defaultdict(int),
            "base_domains": defaultdict(int),
            "service_variants": defaultdict(int),
            "results": results
        }
        
        for result in results:
            summary["categories"][result.get("category", "unknown")] += 1
            summary["protocols"][result.get("protocol", "unknown")] += 1
            summary["base_domains"][result.get("base_domain", result.get("target"))] += 1
            if result.get("service_variant"):
                summary["service_variants"][result["service_variant"]] += 1
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Summary saved to {summary_file}")
        return summary_file
    
    def export_to_csv(self, results: List[Dict]):
        """Export results to CSV format for analysis"""
        csv_file = self.output_dir / f"traceroutes_{self.timestamp}.csv"
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                "timestamp", "vantage_point", "category", "base_domain", 
                "service_variant", "target_ip", "protocol", "port", 
                "num_hops", "success", "duration_seconds",
                "hop_num", "hop_ip", "hop_hostname", "hop_rtt_avg",
                "hop_network", "hop_network_name", "hop_is_interesting"
            ])
            
            # Data rows - one per hop
            for result in results:
                base_row = [
                    result["timestamp"],
                    result["vantage_point"],
                    result.get("category", ""),
                    result.get("base_domain", result["target"]),
                    result.get("service_variant", result["target"]),
                    result["target_ip"],
                    result["protocol"],
                    result.get("port", ""),
                    result["num_hops"],
                    result["success"],
                    result["duration_seconds"]
                ]
                
                for hop in result["hops"]:
                    row = base_row + [
                        hop["hop"],
                        hop["ip"] or "*",
                        hop.get("hostname", ""),
                        hop.get("avg_rtt", ""),
                        hop.get("network", ""),
                        hop.get("network_name", ""),
                        hop.get("is_interesting", "")
                    ]
                    writer.writerow(row)
        
        self.logger.info(f"CSV exported to {csv_file}")
        return csv_file


class TopologyAnalyzer:
    """Analyze collected traceroute data to identify network topology"""
    
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.results = []
        self.logger = logging.getLogger(__name__)
        self.network_discovery = NetworkDiscovery()
    
    def load_results(self, summary_file: str = None):
        """Load results from JSON files"""
        if summary_file:
            with open(summary_file, 'r') as f:
                data = json.load(f)
                self.results = data.get("results", [])
        else:
            # Load from individual files
            raw_dir = self.data_dir / "raw"
            for json_file in raw_dir.glob("*.json"):
                with open(json_file, 'r') as f:
                    self.results.append(json.load(f))
        
        self.logger.info(f"Loaded {len(self.results)} traceroute results")
    
    def analyze_network_paths(self) -> Dict:
        """Analyze network paths and ISP routing patterns"""
        network_stats = defaultdict(lambda: {
            'total_appearances': 0,
            'unique_paths': set(),
            'categories_served': set(),
            'avg_hop_position': [],
            'router_ips': set()
        })
        
        for result in self.results:
            path_analysis = result.get('path_analysis', {})
            
            # Analyze networks traversed
            for network_info in path_analysis.get('networks_traversed', []):
                network = network_info['network']
                network_stats[network]['total_appearances'] += 1
                network_stats[network]['categories_served'].add(result.get('category', 'unknown'))
                
                # Track which paths use this network
                path_key = f"{result.get('vantage_point')}→{result.get('target')}"
                network_stats[network]['unique_paths'].add(path_key)
            
            # Collect interesting router IPs
            for router in path_analysis.get('interesting_routers', []):
                network = router['network']
                network_stats[network]['router_ips'].add(router['ip'])
                network_stats[network]['avg_hop_position'].append(router['hop'])
        
        # Convert sets to lists and calculate averages
        analyzed_networks = {}
        for network, stats in network_stats.items():
            analyzed_networks[network] = {
                'network_name': self.network_discovery.network_patterns.get(network, {}).get('name', network),
                'total_appearances': stats['total_appearances'],
                'unique_paths': len(stats['unique_paths']),
                'categories_served': list(stats['categories_served']),
                'num_categories': len(stats['categories_served']),
                'unique_router_ips': len(stats['router_ips']),
                'router_ips': list(stats['router_ips'])[:20],  # Limit to first 20
                'avg_hop_position': round(sum(stats['avg_hop_position']) / len(stats['avg_hop_position']), 1) if stats['avg_hop_position'] else 0
            }
        
        return analyzed_networks
    
    def find_interesting_routers(self, min_appearances: int = 5) -> Dict[str, List[Dict]]:
        """Find interesting routers grouped by network"""
        router_stats = defaultdict(lambda: defaultdict(lambda: {
            'count': 0,
            'targets': set(),
            'categories': set(),
            'hop_positions': [],
            'hostnames': set()
        }))
        
        for result in self.results:
            for hop in result.get('hops', []):
                if not hop.get('ip') or hop.get('timeout'):
                    continue
                
                network = hop.get('network', 'unknown')
                ip = hop['ip']
                
                router_stats[network][ip]['count'] += 1
                router_stats[network][ip]['targets'].add(result.get('target'))
                router_stats[network][ip]['categories'].add(result.get('category', 'unknown'))
                router_stats[network][ip]['hop_positions'].append(hop['hop'])
                
                if hop.get('hostname'):
                    router_stats[network][ip]['hostnames'].add(hop['hostname'])
        
        # Filter and organize
        interesting_routers_by_network = {}
        
        for network, routers in router_stats.items():
            network_routers = []
            
            for ip, stats in routers.items():
                if stats['count'] >= min_appearances:
                    network_routers.append({
                        'ip': ip,
                        'hostnames': list(stats['hostnames']),
                        'appearances': stats['count'],
                        'unique_targets': len(stats['targets']),
                        'categories': list(stats['categories']),
                        'avg_hop_position': round(sum(stats['hop_positions']) / len(stats['hop_positions']), 1),
                        'hop_range': f"{min(stats['hop_positions'])}-{max(stats['hop_positions'])}"
                    })
            
            if network_routers:
                # Sort by appearances
                network_routers.sort(key=lambda x: x['appearances'], reverse=True)
                interesting_routers_by_network[network] = network_routers
        
        return interesting_routers_by_network
    
    def analyze_network_transitions(self) -> List[Dict]:
        """Analyze transitions between different networks"""
        transitions = defaultdict(lambda: {
            'count': 0,
            'paths': set(),
            'example_ips': []
        })
        
        for result in self.results:
            path_analysis = result.get('path_analysis', {})
            
            for transition in path_analysis.get('network_transitions', []):
                key = f"{transition['from']}→{transition['to']}"
                transitions[key]['count'] += 1
                
                path = f"{result.get('vantage_point')}→{result.get('target')}"
                transitions[key]['paths'].add(path)
                
                # Store example IPs (limit to 5)
                if len(transitions[key]['example_ips']) < 5:
                    transitions[key]['example_ips'].append({
                        'from_ip': transition.get('from_ip'),
                        'to_ip': transition.get('to_ip'),
                        'hop': transition['hop']
                    })
        
        # Convert to list and sort
        transition_list = []
        for key, data in transitions.items():
            from_net, to_net = key.split('→')
            transition_list.append({
                'from_network': from_net,
                'to_network': to_net,
                'occurrences': data['count'],
                'unique_paths': len(data['paths']),
                'example_transitions': data['example_ips']
            })
        
        transition_list.sort(key=lambda x: x['occurrences'], reverse=True)
        return transition_list
    
    def find_core_routers(self, min_appearances: int = 10) -> List[Dict]:
        """Identify core routers that appear in many paths"""
        router_counts = defaultdict(lambda: {
            "count": 0,
            "targets": set(),
            "categories": set(),
            "hop_positions": [],
            "hostname": None,
            "network": "unknown",
            "network_name": "Unknown"
        })
        
        for result in self.results:
            for hop in result["hops"]:
                if hop["ip"] and hop["ip"] != "*":
                    router_counts[hop["ip"]]["count"] += 1
                    router_counts[hop["ip"]]["targets"].add(result["target"])
                    router_counts[hop["ip"]]["categories"].add(result.get("category", "unknown"))
                    router_counts[hop["ip"]]["hop_positions"].append(hop["hop"])
                    
                    if hop.get("hostname") and not router_counts[hop["ip"]]["hostname"]:
                        router_counts[hop["ip"]]["hostname"] = hop["hostname"]
                    
                    if hop.get("network"):
                        router_counts[hop["ip"]]["network"] = hop["network"]
                        router_counts[hop["ip"]]["network_name"] = hop.get("network_name", "Unknown")
        
        # Filter and sort
        core_routers = []
        for ip, data in router_counts.items():
            if data["count"] >= min_appearances:
                core_routers.append({
                    "ip": ip,
                    "hostname": data["hostname"],
                    "network": data["network"],
                    "network_name": data["network_name"],
                    "appearances": data["count"],
                    "unique_targets": len(data["targets"]),
                    "categories": list(data["categories"]),
                    "avg_hop_position": round(sum(data["hop_positions"]) / len(data["hop_positions"]), 1),
                    "hop_range": f"{min(data['hop_positions'])}-{max(data['hop_positions'])}"
                })
        
        core_routers.sort(key=lambda x: x["appearances"], reverse=True)
        return core_routers
    
    def analyze_service_coverage(self) -> Dict:
        """Analyze which domains have multiple services and success rates"""
        domain_services = defaultdict(lambda: {
            "services": set(),
            "successful_services": set(),
            "total_traces": 0,
            "successful_traces": 0
        })
        
        for result in self.results:
            base_domain = result.get("base_domain", result["target"])
            service = result.get("service_variant", result["target"])
            
            domain_services[base_domain]["services"].add(service)
            domain_services[base_domain]["total_traces"] += 1
            
            if result.get("success"):
                domain_services[base_domain]["successful_services"].add(service)
                domain_services[base_domain]["successful_traces"] += 1
        
        # Convert to regular dict for JSON serialization
        coverage = {}
        for domain, data in domain_services.items():
            coverage[domain] = {
                "num_services_tested": len(data["services"]),
                "num_services_successful": len(data["successful_services"]),
                "services": list(data["services"]),
                "successful_services": list(data["successful_services"]),
                "total_traces": data["total_traces"],
                "successful_traces": data["successful_traces"],
                "success_rate": round(data["successful_traces"] / data["total_traces"] * 100, 1)
            }
        
        return coverage
    
    def generate_report(self, output_file: str = None):
        """Generate comprehensive analysis report"""
        if not output_file:
            output_file = self.data_dir / f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("TAIWAN ISP TOPOLOGY MAPPING - ENHANCED ANALYSIS REPORT\n")
            f.write("WITH NETWORK DISCOVERY AND ISP PATH ANALYSIS\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total traceroutes: {len(self.results)}\n")
            successful = sum(1 for r in self.results if r.get('success'))
            f.write(f"Successful: {successful} ({successful/len(self.results)*100:.1f}%)\n")
            f.write(f"Failed: {len(self.results) - successful}\n\n")
            
            # Network path analysis
            f.write("NETWORK PATH ANALYSIS\n")
            f.write("=" * 80 + "\n\n")
            
            network_analysis = self.analyze_network_paths()
            
            # Sort by total appearances
            sorted_networks = sorted(
                network_analysis.items(),
                key=lambda x: x[1]['total_appearances'],
                reverse=True
            )
            
            f.write("Networks Encountered (sorted by frequency):\n")
            f.write("-" * 80 + "\n")
            for network, stats in sorted_networks:
                f.write(f"\n{stats['network_name']} ({network})\n")
                f.write(f"  Total appearances: {stats['total_appearances']}\n")
                f.write(f"  Unique paths: {stats['unique_paths']}\n")
                f.write(f"  Categories served: {stats['num_categories']}\n")
                f.write(f"  Avg hop position: {stats['avg_hop_position']}\n")
                f.write(f"  Unique router IPs: {stats['unique_router_ips']}\n")
            
            # Network transitions
            f.write("\n\nNETWORK TRANSITIONS (Inter-ISP Routing)\n")
            f.write("=" * 80 + "\n")
            transitions = self.analyze_network_transitions()
            
            f.write(f"\nTop {min(20, len(transitions))} Most Common Network Transitions:\n")
            f.write("-" * 80 + "\n")
            for i, trans in enumerate(transitions[:20], 1):
                f.write(f"\n{i}. {trans['from_network']} → {trans['to_network']}\n")
                f.write(f"   Occurrences: {trans['occurrences']}\n")
                f.write(f"   Unique paths: {trans['unique_paths']}\n")
                if trans['example_transitions']:
                    f.write(f"   Example: {trans['example_transitions'][0]['from_ip']} → ")
                    f.write(f"{trans['example_transitions'][0]['to_ip']} (hop {trans['example_transitions'][0]['hop']})\n")
            
            # Interesting routers by network
            f.write("\n\nINTERESTING ROUTERS BY NETWORK\n")
            f.write("=" * 80 + "\n")
            
            interesting_routers = self.find_interesting_routers(min_appearances=5)
            
            for network in ['hinet', 'twaren', 'seednet', 'fetnet', 'university', 'government']:
                if network in interesting_routers:
                    routers = interesting_routers[network]
                    network_name = self.network_discovery.network_patterns.get(network, {}).get('name', network)
                    
                    f.write(f"\n{network_name.upper()} ({network})\n")
                    f.write("-" * 80 + "\n")
                    f.write(f"Found {len(routers)} interesting routers\n\n")
                    
                    for i, router in enumerate(routers[:10], 1):  # Top 10 per network
                        f.write(f"{i}. {router['ip']}\n")
                        if router['hostnames']:
                            f.write(f"   Hostname: {router['hostnames'][0]}\n")
                        f.write(f"   Appearances: {router['appearances']}\n")
                        f.write(f"   Unique targets: {router['unique_targets']}\n")
                        f.write(f"   Avg hop: {router['avg_hop_position']} (range: {router['hop_range']})\n")
                        f.write(f"   Categories: {', '.join(router['categories'][:5])}\n")
                        f.write("\n")
            
            # Service coverage analysis
            f.write("\nSERVICE COVERAGE ANALYSIS\n")
            f.write("=" * 80 + "\n")
            coverage = self.analyze_service_coverage()
            
            # Sort by success rate
            sorted_coverage = sorted(
                coverage.items(),
                key=lambda x: x[1]["success_rate"],
                reverse=True
            )
            
            f.write(f"\nTop {min(30, len(sorted_coverage))} Domains by Success Rate:\n")
            f.write("-" * 80 + "\n")
            for domain, data in sorted_coverage[:30]:
                f.write(f"\n{domain}\n")
                f.write(f"  Services tested: {data['num_services_tested']}\n")
                f.write(f"  Successful: {data['num_services_successful']}\n")
                f.write(f"  Success rate: {data['success_rate']}%\n")
                if data['successful_services']:
                    f.write(f"  Working services: {', '.join(list(data['successful_services'])[:5])}\n")
            
            # Core routers (all networks combined)
            f.write("\n\nCORE ROUTERS (All Networks, 10+ appearances)\n")
            f.write("=" * 80 + "\n")
            core_routers = self.find_core_routers(min_appearances=10)
            
            f.write(f"\nFound {len(core_routers)} core routers\n")
            f.write("-" * 80 + "\n")
            for i, router in enumerate(core_routers[:30], 1):
                f.write(f"\n{i}. {router['ip']}")
                if router['hostname']:
                    f.write(f" ({router['hostname']})")
                f.write(f"\n   Network: {router['network_name']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique targets: {router['unique_targets']}\n")
                f.write(f"   Avg hop: {router['avg_hop_position']} (range: {router['hop_range']})\n")
        
        self.logger.info(f"Analysis report saved to {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Taiwan ISP Topology Mapper - Enhanced Edition with Network Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick collection with service discovery (www + bare domain only)
  %(prog)s --vantage-point university --max-services 2
  
  # Full collection with multiple service variants
  %(prog)s --vantage-point university --max-services 5
  
  # Disable service discovery (original behavior)
  %(prog)s --vantage-point university --no-service-discovery
  
  # Test specific category with all services
  %(prog)s --vantage-point cht-mobile --category financial_banks --max-services 10
        """
    )
    
    parser.add_argument("--vantage-point", required=True, 
                       choices=["university", "cht-mobile", "itaiwan"],
                       help="Vantage point identifier")
    parser.add_argument("--category", 
                       help="Specific category to trace (default: all)")
    parser.add_argument("--protocols", nargs="+", 
                       default=["icmp", "tcp-80", "tcp-443"],
                       help="Protocols to use (e.g., icmp tcp-80 tcp-443)")
    parser.add_argument("--output-dir", default="traceroute_data",
                       help="Output directory for results")
    parser.add_argument("--delay", type=float, default=1.0,
                       help="Delay between traceroutes in seconds")
    parser.add_argument("--no-service-discovery", action="store_true",
                       help="Disable service discovery (test only bare domains)")
    parser.add_argument("--max-services", type=int, default=3,
                       help="Maximum service variants to test per domain (default: 3)")
    parser.add_argument("--analyze-only", 
                       help="Only analyze existing data (provide summary JSON file)")
    
    args = parser.parse_args()
    
    if args.analyze_only:
        # Analysis mode
        analyzer = TopologyAnalyzer(args.output_dir)
        analyzer.load_results(args.analyze_only)
        analyzer.generate_report()
    else:
        # Collection mode
        collector = TracerouteCollector(
            output_dir=args.output_dir,
            vantage_point=args.vantage_point
        )
        
        print(f"\n{'='*80}")
        print(f"Taiwan ISP Topology Mapping - Enhanced Data Collection")
        print(f"WITH NETWORK DISCOVERY AND ISP PATH ANALYSIS")
        print(f"{'='*80}")
        print(f"Vantage Point: {args.vantage_point}")
        print(f"Category: {args.category or 'ALL'}")
        print(f"Protocols: {', '.join(args.protocols)}")
        print(f"Service Discovery: {'Enabled' if not args.no_service_discovery else 'Disabled'}")
        if not args.no_service_discovery:
            print(f"Max Services/Domain: {args.max_services}")
        print(f"Output Directory: {args.output_dir}")
        print(f"{'='*80}\n")
        
        # Collect data
        results = collector.collect_batch(
            category=args.category,
            protocols=args.protocols,
            delay=args.delay,
            service_discovery=not args.no_service_discovery,
            max_services_per_domain=args.max_services
        )
        
        # Save summary and export
        summary_file = collector.save_summary(results)
        csv_file = collector.export_to_csv(results)
        
        print(f"\n{'='*80}")
        print(f"Collection Complete!")
        print(f"{'='*80}")
        print(f"Total traceroutes: {len(results)}")
        print(f"Successful: {sum(1 for r in results if r.get('success'))}")
        print(f"Failed: {sum(1 for r in results if not r.get('success'))}")
        print(f"Summary: {summary_file}")
        print(f"CSV export: {csv_file}")
        print(f"{'='*80}\n")
        
        # Run analysis
        print("Running analysis...")
        analyzer = TopologyAnalyzer(args.output_dir)
        analyzer.load_results(summary_file)
        report_file = analyzer.generate_report()
        print(f"Analysis report: {report_file}\n")


if __name__ == "__main__":
    main()