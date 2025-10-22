#!/usr/bin/env python3
"""
Taiwan ISP Topology Mapping - Enhanced Traceroute Collection System
Research: HiNet (AS3462), SEEDnet (AS4780), Taiwan Fixed Network (AS9924)

Enhanced Features:
- Tests multiple service variants per domain (www, mail, ftp, etc.)
- Tests common service ports (HTTP, HTTPS, SMTP, DNS, etc.)
- Improved success rate through service discovery
- Collects and identifies interesting routers with reverse DNS
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

class TracerouteCollector:
    def __init__(self, output_dir: str = "traceroute_data", vantage_point: str = "unknown"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.vantage_point = vantage_point
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
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
        
        # Interesting router collection
        self.interesting_routers = {}  # Dict[ip] -> {hostname, appearances, targets, categories}
        
        # Collect ALL routers with hostnames (not just pattern-matched ones)
        self.collect_all_named_routers = True
        
        # Patterns for highlighting particularly interesting routers (optional filtering)
        self.interesting_patterns = [
            r'hinet\.net',
            r'seednet\.net',
            r'so-net\.net',
            r'fixednet\.tw',
            r'tfn\.net\.tw',
            r'fxn\.tw',
            r'\.gov\.tw',
            r'\.edu\.tw',
            r'tanet\.edu\.tw',
            r'twaren\.net',
            r'cht\.com\.tw',
            r'fetnet\.net',
            r'taiwanmobile\.com',
            r'aptg\.com\.tw',
            r'chief\.com\.tw',
            r'tpix\.net',
            r'\.tw',
            r'\.com\.tw',
            r'\.net\.tw',
        ]
        
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
                "139.175.150.20", "203.133.1.8", "210.241.0.4", "139.175.1.1"
            ],
            "education_network": [
                "twaren.net", "tanet.edu.tw", "nchc.org.tw", "sinica.edu.tw"
            ]
        }
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.logger.debug(f"Reverse DNS: {ip} -> {hostname}")
            return hostname
        except (socket.herror, socket.gaierror):
            self.logger.debug(f"No reverse DNS for {ip}")
            return None
    
    def is_interesting_router(self, hostname: str) -> bool:
        """Check if hostname matches interesting patterns"""
        if not hostname:
            return False
        
        for pattern in self.interesting_patterns:
            if re.search(pattern, hostname, re.IGNORECASE):
                return True
        return False
    
    def add_interesting_router(self, ip: str, hostname: str, target: str, category: str):
        """Add a router to the interesting routers collection"""
        if ip not in self.interesting_routers:
            self.interesting_routers[ip] = {
                "hostname": hostname,
                "ip": ip,
                "appearances": 0,
                "targets": set(),
                "categories": set()
            }
        
        router = self.interesting_routers[ip]
        router["appearances"] += 1
        router["targets"].add(target)
        router["categories"].add(category)
    
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
        
        # Build traceroute command
        cmd = self._build_traceroute_cmd(ip, protocol, port, max_hops)
        
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
            
            # Parse output and collect interesting routers
            hops = self._parse_traceroute_output(
                result.stdout, 
                target, 
                metadata.get("category", "unknown") if metadata else "unknown"
            )
            
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
                             port: int, max_hops: int) -> List[str]:
        """Build traceroute command based on protocol"""
        base_cmd = ["traceroute", "-w", "3", "-q", "3", "-m", str(max_hops)]
        
        if protocol == "icmp":
            cmd = base_cmd + ["-I", ip]
        elif protocol == "udp":
            cmd = base_cmd + ["-p", str(port), ip]
        elif protocol == "tcp":
            cmd = base_cmd + ["-T", "-p", str(port), ip]
        else:
            cmd = base_cmd + [ip]
        
        return cmd
    
    def _parse_traceroute_output(self, output: str, target: str, category: str) -> List[Dict]:
        """Parse traceroute output into structured format and collect interesting routers"""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip first line (header)
            hop = self._parse_hop_line(line, target, category)
            if hop:
                hops.append(hop)
        
        return hops
    
    def _parse_hop_line(self, line: str, target: str, category: str) -> Optional[Dict]:
        """Parse a single hop line from traceroute output and collect interesting routers"""
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
            
            # Check if we have hostname (parts[1]) or IP
            if '(' in line and ')' in line:
                # Format: "hostname (ip)"
                hostname_match = re.search(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)', line)
                if hostname_match:
                    hostname = hostname_match.group(1)
                    ip = hostname_match.group(2)
                else:
                    ip = parts[1]
                    hostname = self.reverse_dns_lookup(ip)
            else:
                # Only IP provided
                ip = parts[1]
                hostname = self.reverse_dns_lookup(ip)
            
            # Check if this is an interesting router
            if hostname and self.is_interesting_router(hostname):
                self.add_interesting_router(ip, hostname, target, category)
                self.logger.info(f"Found interesting router: {hostname} ({ip})")
            
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
    
    def save_interesting_routers(self):
        """Save interesting routers to JSON and text files"""
        # Convert sets to lists for JSON serialization
        routers_for_json = []
        for ip, data in self.interesting_routers.items():
            router_data = data.copy()
            router_data["targets"] = list(data["targets"])
            router_data["categories"] = list(data["categories"])
            routers_for_json.append(router_data)
        
        # Sort by appearances
        routers_for_json.sort(key=lambda x: x["appearances"], reverse=True)
        
        # Save JSON
        json_file = self.output_dir / f"interesting_routers_{self.timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                "timestamp": self.timestamp,
                "vantage_point": self.vantage_point,
                "total_routers": len(routers_for_json),
                "routers": routers_for_json
            }, f, indent=2)
        
        self.logger.info(f"Interesting routers JSON saved to {json_file}")
        
        # Save human-readable text file
        txt_file = self.output_dir / f"interesting_routers_{self.timestamp}.txt"
        with open(txt_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("INTERESTING ROUTERS DISCOVERED\n")
            f.write("=" * 80 + "\n")
            f.write(f"Collection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.vantage_point}\n")
            f.write(f"Total Interesting Routers: {len(routers_for_json)}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, router in enumerate(routers_for_json, 1):
                f.write(f"{i}. {router['hostname']}\n")
                f.write(f"   IP: {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique Targets: {len(router['targets'])}\n")
                f.write(f"   Categories: {', '.join(router['categories'])}\n")
                f.write(f"   Sample Targets: {', '.join(list(router['targets'])[:5])}\n")
                if len(router['targets']) > 5:
                    f.write(f"   ... and {len(router['targets']) - 5} more\n")
                f.write("\n")
        
        self.logger.info(f"Interesting routers text file saved to {txt_file}")
        
        return json_file, txt_file
    
    def print_interesting_routers_summary(self):
        """Print a summary of interesting routers to console"""
        if not self.interesting_routers:
            print("\nNo interesting routers found.")
            return
        
        # Convert and sort
        routers_list = []
        for ip, data in self.interesting_routers.items():
            routers_list.append({
                "ip": ip,
                "hostname": data["hostname"],
                "appearances": data["appearances"],
                "num_targets": len(data["targets"]),
                "categories": list(data["categories"])
            })
        
        routers_list.sort(key=lambda x: x["appearances"], reverse=True)
        
        print(f"\n{'='*80}")
        print(f"INTERESTING ROUTERS DISCOVERED: {len(routers_list)}")
        print(f"{'='*80}\n")
        
        # Print top 20
        for i, router in enumerate(routers_list[:20], 1):
            print(f"{i}. {router['hostname']}")
            print(f"   IP: {router['ip']}")
            print(f"   Appearances: {router['appearances']} | Unique Targets: {router['num_targets']}")
            print(f"   Categories: {', '.join(router['categories'])}")
            print()
        
        if len(routers_list) > 20:
            print(f"... and {len(routers_list) - 20} more routers")
            print(f"\nSee full list in the saved files.\n")
    
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
                "hop_num", "hop_ip", "hop_hostname", "hop_rtt_avg"
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
                        hop.get("avg_rtt", "")
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
    
    def find_core_routers(self, min_appearances: int = 10) -> List[Dict]:
        """Identify core routers that appear in many paths"""
        router_counts = defaultdict(lambda: {
            "count": 0,
            "targets": set(),
            "categories": set(),
            "hop_positions": []
        })
        
        for result in self.results:
            for hop in result["hops"]:
                if hop["ip"] and hop["ip"] != "*":
                    router_counts[hop["ip"]]["count"] += 1
                    router_counts[hop["ip"]]["targets"].add(result["target"])
                    router_counts[hop["ip"]]["categories"].add(result.get("category", "unknown"))
                    router_counts[hop["ip"]]["hop_positions"].append(hop["hop"])
        
        # Filter and sort
        core_routers = []
        for ip, data in router_counts.items():
            if data["count"] >= min_appearances:
                core_routers.append({
                    "ip": ip,
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
            f.write("=" * 80 + "\n\n")
            
            # Summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total traceroutes: {len(self.results)}\n")
            successful = sum(1 for r in self.results if r.get('success'))
            f.write(f"Successful: {successful} ({successful/len(self.results)*100:.1f}%)\n")
            f.write(f"Failed: {len(self.results) - successful}\n\n")
            
            # Service coverage analysis
            f.write("SERVICE COVERAGE ANALYSIS\n")
            f.write("-" * 80 + "\n")
            coverage = self.analyze_service_coverage()
            
            # Sort by success rate
            sorted_coverage = sorted(
                coverage.items(),
                key=lambda x: x[1]["success_rate"],
                reverse=True
            )
            
            for domain, data in sorted_coverage[:30]:  # Top 30
                f.write(f"\n{domain}\n")
                f.write(f"  Services tested: {data['num_services_tested']}\n")
                f.write(f"  Successful: {data['num_services_successful']}\n")
                f.write(f"  Success rate: {data['success_rate']}%\n")
                f.write(f"  Working services: {', '.join(data['successful_services']) or 'None'}\n")
            
            # Core routers
            f.write("\n\nCORE ROUTERS (appearing in 10+ paths)\n")
            f.write("-" * 80 + "\n")
            core_routers = self.find_core_routers(min_appearances=10)
            for i, router in enumerate(core_routers[:20], 1):
                f.write(f"{i}. {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique targets: {router['unique_targets']}\n")
                f.write(f"   Avg hop position: {router['avg_hop_position']}\n\n")
        
        self.logger.info(f"Analysis report saved to {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Taiwan ISP Topology Mapper - Enhanced Edition",
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
        
        # Save and print interesting routers
        router_json, router_txt = collector.save_interesting_routers()
        collector.print_interesting_routers_summary()
        
        print(f"\n{'='*80}")
        print(f"Collection Complete!")
        print(f"{'='*80}")
        print(f"Total traceroutes: {len(results)}")
        print(f"Successful: {sum(1 for r in results if r.get('success'))}")
        print(f"Failed: {sum(1 for r in results if not r.get('success'))}")
        print(f"Summary: {summary_file}")
        print(f"CSV export: {csv_file}")
        print(f"Interesting routers JSON: {router_json}")
        print(f"Interesting routers TXT: {router_txt}")
        print(f"{'='*80}\n")
        
        # Run analysis
        print("Running analysis...")
        analyzer = TopologyAnalyzer(args.output_dir)
        analyzer.load_results(summary_file)
        report_file = analyzer.generate_report()
        print(f"Analysis report: {report_file}\n")


if __name__ == "__main__":
    main()
        
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
                "139.175.150.20", "203.133.1.8", "210.241.0.4", "139.175.1.1"
            ],
            "education_network": [
                "twaren.net", "tanet.edu.tw", "nchc.org.tw", "sinica.edu.tw"
            ]
        }
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.logger.debug(f"Reverse DNS: {ip} -> {hostname}")
            return hostname
        except (socket.herror, socket.gaierror):
            self.logger.debug(f"No reverse DNS for {ip}")
            return None
    
    def is_interesting_router(self, hostname: str) -> bool:
        """Check if hostname matches interesting patterns"""
        if not hostname:
            return False
        
        for pattern in self.interesting_patterns:
            if re.search(pattern, hostname, re.IGNORECASE):
                return True
        return False
    
    def add_interesting_router(self, ip: str, hostname: str, target: str, category: str):
        """Add a router to the interesting routers collection"""
        if ip not in self.interesting_routers:
            self.interesting_routers[ip] = {
                "hostname": hostname,
                "ip": ip,
                "appearances": 0,
                "targets": set(),
                "categories": set()
            }
        
        router = self.interesting_routers[ip]
        router["appearances"] += 1
        router["targets"].add(target)
        router["categories"].add(category)
    
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
        
        # Build traceroute command
        cmd = self._build_traceroute_cmd(ip, protocol, port, max_hops)
        
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
            
            # Parse output and collect interesting routers
            hops = self._parse_traceroute_output(
                result.stdout, 
                target, 
                metadata.get("category", "unknown") if metadata else "unknown"
            )
            
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
                             port: int, max_hops: int) -> List[str]:
        """Build traceroute command based on protocol"""
        base_cmd = ["traceroute", "-w", "3", "-q", "3", "-m", str(max_hops)]
        
        if protocol == "icmp":
            cmd = base_cmd + ["-I", ip]
        elif protocol == "udp":
            cmd = base_cmd + ["-p", str(port), ip]
        elif protocol == "tcp":
            cmd = base_cmd + ["-T", "-p", str(port), ip]
        else:
            cmd = base_cmd + [ip]
        
        return cmd
    
    def _parse_traceroute_output(self, output: str, target: str, category: str) -> List[Dict]:
        """Parse traceroute output into structured format and collect interesting routers"""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip first line (header)
            hop = self._parse_hop_line(line, target, category)
            if hop:
                hops.append(hop)
        
        return hops
    
    def _parse_hop_line(self, line: str, target: str, category: str) -> Optional[Dict]:
        """Parse a single hop line from traceroute output and collect interesting routers"""
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
            
            # Check if we have hostname (parts[1]) or IP
            if '(' in line and ')' in line:
                # Format: "hostname (ip)"
                hostname_match = re.search(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)', line)
                if hostname_match:
                    hostname = hostname_match.group(1)
                    ip = hostname_match.group(2)
                else:
                    ip = parts[1]
                    hostname = self.reverse_dns_lookup(ip)
            else:
                # Only IP provided
                ip = parts[1]
                hostname = self.reverse_dns_lookup(ip)
            
            # Check if this is an interesting router
            if hostname and self.is_interesting_router(hostname):
                self.add_interesting_router(ip, hostname, target, category)
                self.logger.info(f"Found interesting router: {hostname} ({ip})")
            
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
    
    def save_interesting_routers(self):
        """Save interesting routers to JSON and text files"""
        # Convert sets to lists for JSON serialization
        routers_for_json = []
        for ip, data in self.interesting_routers.items():
            router_data = data.copy()
            router_data["targets"] = list(data["targets"])
            router_data["categories"] = list(data["categories"])
            routers_for_json.append(router_data)
        
        # Sort by appearances
        routers_for_json.sort(key=lambda x: x["appearances"], reverse=True)
        
        # Save JSON
        json_file = self.output_dir / f"interesting_routers_{self.timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                "timestamp": self.timestamp,
                "vantage_point": self.vantage_point,
                "total_routers": len(routers_for_json),
                "routers": routers_for_json
            }, f, indent=2)
        
        self.logger.info(f"Interesting routers JSON saved to {json_file}")
        
        # Save human-readable text file
        txt_file = self.output_dir / f"interesting_routers_{self.timestamp}.txt"
        with open(txt_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("INTERESTING ROUTERS DISCOVERED\n")
            f.write("=" * 80 + "\n")
            f.write(f"Collection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.vantage_point}\n")
            f.write(f"Total Interesting Routers: {len(routers_for_json)}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, router in enumerate(routers_for_json, 1):
                f.write(f"{i}. {router['hostname']}\n")
                f.write(f"   IP: {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique Targets: {len(router['targets'])}\n")
                f.write(f"   Categories: {', '.join(router['categories'])}\n")
                f.write(f"   Sample Targets: {', '.join(list(router['targets'])[:5])}\n")
                if len(router['targets']) > 5:
                    f.write(f"   ... and {len(router['targets']) - 5} more\n")
                f.write("\n")
        
        self.logger.info(f"Interesting routers text file saved to {txt_file}")
        
        return json_file, txt_file
    
    def print_interesting_routers_summary(self):
        """Print a summary of interesting routers to console"""
        if not self.interesting_routers:
            print("\nNo interesting routers found.")
            return
        
        # Convert and sort
        routers_list = []
        for ip, data in self.interesting_routers.items():
            routers_list.append({
                "ip": ip,
                "hostname": data["hostname"],
                "appearances": data["appearances"],
                "num_targets": len(data["targets"]),
                "categories": list(data["categories"])
            })
        
        routers_list.sort(key=lambda x: x["appearances"], reverse=True)
        
        print(f"\n{'='*80}")
        print(f"INTERESTING ROUTERS DISCOVERED: {len(routers_list)}")
        print(f"{'='*80}\n")
        
        # Print top 20
        for i, router in enumerate(routers_list[:20], 1):
            print(f"{i}. {router['hostname']}")
            print(f"   IP: {router['ip']}")
            print(f"   Appearances: {router['appearances']} | Unique Targets: {router['num_targets']}")
            print(f"   Categories: {', '.join(router['categories'])}")
            print()
        
        if len(routers_list) > 20:
            print(f"... and {len(routers_list) - 20} more routers")
            print(f"\nSee full list in the saved files.\n")
    
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
                "hop_num", "hop_ip", "hop_hostname", "hop_rtt_avg"
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
                        hop.get("avg_rtt", "")
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
    
    def find_core_routers(self, min_appearances: int = 10) -> List[Dict]:
        """Identify core routers that appear in many paths"""
        router_counts = defaultdict(lambda: {
            "count": 0,
            "targets": set(),
            "categories": set(),
            "hop_positions": []
        })
        
        for result in self.results:
            for hop in result["hops"]:
                if hop["ip"] and hop["ip"] != "*":
                    router_counts[hop["ip"]]["count"] += 1
                    router_counts[hop["ip"]]["targets"].add(result["target"])
                    router_counts[hop["ip"]]["categories"].add(result.get("category", "unknown"))
                    router_counts[hop["ip"]]["hop_positions"].append(hop["hop"])
        
        # Filter and sort
        core_routers = []
        for ip, data in router_counts.items():
            if data["count"] >= min_appearances:
                core_routers.append({
                    "ip": ip,
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
            f.write("=" * 80 + "\n\n")
            
            # Summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total traceroutes: {len(self.results)}\n")
            successful = sum(1 for r in self.results if r.get('success'))
            f.write(f"Successful: {successful} ({successful/len(self.results)*100:.1f}%)\n")
            f.write(f"Failed: {len(self.results) - successful}\n\n")
            
            # Service coverage analysis
            f.write("SERVICE COVERAGE ANALYSIS\n")
            f.write("-" * 80 + "\n")
            coverage = self.analyze_service_coverage()
            
            # Sort by success rate
            sorted_coverage = sorted(
                coverage.items(),
                key=lambda x: x[1]["success_rate"],
                reverse=True
            )
            
            for domain, data in sorted_coverage[:30]:  # Top 30
                f.write(f"\n{domain}\n")
                f.write(f"  Services tested: {data['num_services_tested']}\n")
                f.write(f"  Successful: {data['num_services_successful']}\n")
                f.write(f"  Success rate: {data['success_rate']}%\n")
                f.write(f"  Working services: {', '.join(data['successful_services']) or 'None'}\n")
            
            # Core routers
            f.write("\n\nCORE ROUTERS (appearing in 10+ paths)\n")
            f.write("-" * 80 + "\n")
            core_routers = self.find_core_routers(min_appearances=10)
            for i, router in enumerate(core_routers[:20], 1):
                f.write(f"{i}. {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique targets: {router['unique_targets']}\n")
                f.write(f"   Avg hop position: {router['avg_hop_position']}\n\n")
        
        self.logger.info(f"Analysis report saved to {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Taiwan ISP Topology Mapper - Enhanced Edition",
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
        
        # Save and print interesting routers
        router_json, router_txt = collector.save_interesting_routers()
        collector.print_interesting_routers_summary()
        
        print(f"\n{'='*80}")
        print(f"Collection Complete!")
        print(f"{'='*80}")
        print(f"Total traceroutes: {len(results)}")
        print(f"Successful: {sum(1 for r in results if r.get('success'))}")
        print(f"Failed: {sum(1 for r in results if not r.get('success'))}")
        print(f"Summary: {summary_file}")
        print(f"CSV export: {csv_file}")
        print(f"Interesting routers JSON: {router_json}")
        print(f"Interesting routers TXT: {router_txt}")
        print(f"{'='*80}\n")
        
        # Run analysis
        print("Running analysis...")
        analyzer = TopologyAnalyzer(args.output_dir)
        analyzer.load_results(summary_file)
        report_file = analyzer.generate_report()
        print(f"Analysis report: {report_file}\n")


if __name__ == "__main__":
    main()
        
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
                "139.175.150.20", "203.133.1.8", "210.241.0.4", "139.175.1.1"
            ],
            "education_network": [
                "twaren.net", "tanet.edu.tw", "nchc.org.tw", "sinica.edu.tw"
            ]
        }
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.logger.debug(f"Reverse DNS: {ip} -> {hostname}")
            return hostname
        except (socket.herror, socket.gaierror):
            self.logger.debug(f"No reverse DNS for {ip}")
            return None
    
    def is_interesting_router(self, hostname: str) -> bool:
        """Check if hostname matches interesting patterns"""
        if not hostname:
            return False
        
        for pattern in self.interesting_patterns:
            if re.search(pattern, hostname, re.IGNORECASE):
                return True
        return False
    
    def add_interesting_router(self, ip: str, hostname: str, target: str, category: str):
        """Add a router to the interesting routers collection"""
        if ip not in self.interesting_routers:
            self.interesting_routers[ip] = {
                "hostname": hostname,
                "ip": ip,
                "appearances": 0,
                "targets": set(),
                "categories": set()
            }
        
        router = self.interesting_routers[ip]
        router["appearances"] += 1
        router["targets"].add(target)
        router["categories"].add(category)
    
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
        
        # Build traceroute command
        cmd = self._build_traceroute_cmd(ip, protocol, port, max_hops)
        
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
            
            # Parse output and collect interesting routers
            hops = self._parse_traceroute_output(
                result.stdout, 
                target, 
                metadata.get("category", "unknown") if metadata else "unknown"
            )
            
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
                             port: int, max_hops: int) -> List[str]:
        """Build traceroute command based on protocol"""
        base_cmd = ["traceroute", "-w", "3", "-q", "3", "-m", str(max_hops)]
        
        if protocol == "icmp":
            cmd = base_cmd + ["-I", ip]
        elif protocol == "udp":
            cmd = base_cmd + ["-p", str(port), ip]
        elif protocol == "tcp":
            cmd = base_cmd + ["-T", "-p", str(port), ip]
        else:
            cmd = base_cmd + [ip]
        
        return cmd
    
    def _parse_traceroute_output(self, output: str, target: str, category: str) -> List[Dict]:
        """Parse traceroute output into structured format and collect interesting routers"""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip first line (header)
            hop = self._parse_hop_line(line, target, category)
            if hop:
                hops.append(hop)
        
        return hops
    
    def _parse_hop_line(self, line: str, target: str, category: str) -> Optional[Dict]:
        """Parse a single hop line from traceroute output and collect interesting routers"""
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
            
            # Check if we have hostname (parts[1]) or IP
            if '(' in line and ')' in line:
                # Format: "hostname (ip)"
                hostname_match = re.search(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)', line)
                if hostname_match:
                    hostname = hostname_match.group(1)
                    ip = hostname_match.group(2)
                else:
                    ip = parts[1]
                    hostname = self.reverse_dns_lookup(ip)
            else:
                # Only IP provided
                ip = parts[1]
                hostname = self.reverse_dns_lookup(ip)
            
            # Check if this is an interesting router
            if hostname and self.is_interesting_router(hostname):
                self.add_interesting_router(ip, hostname, target, category)
                self.logger.info(f"Found interesting router: {hostname} ({ip})")
            
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
    
    def save_interesting_routers(self):
        """Save interesting routers to JSON and text files"""
        # Convert sets to lists for JSON serialization
        routers_for_json = []
        for ip, data in self.interesting_routers.items():
            router_data = data.copy()
            router_data["targets"] = list(data["targets"])
            router_data["categories"] = list(data["categories"])
            routers_for_json.append(router_data)
        
        # Sort by appearances
        routers_for_json.sort(key=lambda x: x["appearances"], reverse=True)
        
        # Save JSON
        json_file = self.output_dir / f"interesting_routers_{self.timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                "timestamp": self.timestamp,
                "vantage_point": self.vantage_point,
                "total_routers": len(routers_for_json),
                "routers": routers_for_json
            }, f, indent=2)
        
        self.logger.info(f"Interesting routers JSON saved to {json_file}")
        
        # Save human-readable text file
        txt_file = self.output_dir / f"interesting_routers_{self.timestamp}.txt"
        with open(txt_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("INTERESTING ROUTERS DISCOVERED\n")
            f.write("=" * 80 + "\n")
            f.write(f"Collection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.vantage_point}\n")
            f.write(f"Total Interesting Routers: {len(routers_for_json)}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, router in enumerate(routers_for_json, 1):
                f.write(f"{i}. {router['hostname']}\n")
                f.write(f"   IP: {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique Targets: {len(router['targets'])}\n")
                f.write(f"   Categories: {', '.join(router['categories'])}\n")
                f.write(f"   Sample Targets: {', '.join(list(router['targets'])[:5])}\n")
                if len(router['targets']) > 5:
                    f.write(f"   ... and {len(router['targets']) - 5} more\n")
                f.write("\n")
        
        self.logger.info(f"Interesting routers text file saved to {txt_file}")
        
        return json_file, txt_file
    
    def print_interesting_routers_summary(self):
        """Print a summary of interesting routers to console"""
        if not self.interesting_routers:
            print("\nNo interesting routers found.")
            return
        
        # Convert and sort
        routers_list = []
        for ip, data in self.interesting_routers.items():
            routers_list.append({
                "ip": ip,
                "hostname": data["hostname"],
                "appearances": data["appearances"],
                "num_targets": len(data["targets"]),
                "categories": list(data["categories"])
            })
        
        routers_list.sort(key=lambda x: x["appearances"], reverse=True)
        
        print(f"\n{'='*80}")
        print(f"INTERESTING ROUTERS DISCOVERED: {len(routers_list)}")
        print(f"{'='*80}\n")
        
        # Print top 20
        for i, router in enumerate(routers_list[:20], 1):
            print(f"{i}. {router['hostname']}")
            print(f"   IP: {router['ip']}")
            print(f"   Appearances: {router['appearances']} | Unique Targets: {router['num_targets']}")
            print(f"   Categories: {', '.join(router['categories'])}")
            print()
        
        if len(routers_list) > 20:
            print(f"... and {len(routers_list) - 20} more routers")
            print(f"\nSee full list in the saved files.\n")
    
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
                "hop_num", "hop_ip", "hop_hostname", "hop_rtt_avg"
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
                        hop.get("avg_rtt", "")
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
    
    def find_core_routers(self, min_appearances: int = 10) -> List[Dict]:
        """Identify core routers that appear in many paths"""
        router_counts = defaultdict(lambda: {
            "count": 0,
            "targets": set(),
            "categories": set(),
            "hop_positions": []
        })
        
        for result in self.results:
            for hop in result["hops"]:
                if hop["ip"] and hop["ip"] != "*":
                    router_counts[hop["ip"]]["count"] += 1
                    router_counts[hop["ip"]]["targets"].add(result["target"])
                    router_counts[hop["ip"]]["categories"].add(result.get("category", "unknown"))
                    router_counts[hop["ip"]]["hop_positions"].append(hop["hop"])
        
        # Filter and sort
        core_routers = []
        for ip, data in router_counts.items():
            if data["count"] >= min_appearances:
                core_routers.append({
                    "ip": ip,
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
            f.write("=" * 80 + "\n\n")
            
            # Summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total traceroutes: {len(self.results)}\n")
            successful = sum(1 for r in self.results if r.get('success'))
            f.write(f"Successful: {successful} ({successful/len(self.results)*100:.1f}%)\n")
            f.write(f"Failed: {len(self.results) - successful}\n\n")
            
            # Service coverage analysis
            f.write("SERVICE COVERAGE ANALYSIS\n")
            f.write("-" * 80 + "\n")
            coverage = self.analyze_service_coverage()
            
            # Sort by success rate
            sorted_coverage = sorted(
                coverage.items(),
                key=lambda x: x[1]["success_rate"],
                reverse=True
            )
            
            for domain, data in sorted_coverage[:30]:  # Top 30
                f.write(f"\n{domain}\n")
                f.write(f"  Services tested: {data['num_services_tested']}\n")
                f.write(f"  Successful: {data['num_services_successful']}\n")
                f.write(f"  Success rate: {data['success_rate']}%\n")
                f.write(f"  Working services: {', '.join(data['successful_services']) or 'None'}\n")
            
            # Core routers
            f.write("\n\nCORE ROUTERS (appearing in 10+ paths)\n")
            f.write("-" * 80 + "\n")
            core_routers = self.find_core_routers(min_appearances=10)
            for i, router in enumerate(core_routers[:20], 1):
                f.write(f"{i}. {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique targets: {router['unique_targets']}\n")
                f.write(f"   Avg hop position: {router['avg_hop_position']}\n\n")
        
        self.logger.info(f"Analysis report saved to {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Taiwan ISP Topology Mapper - Enhanced Edition",
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
        
        # Save and print interesting routers
        router_json, router_txt = collector.save_interesting_routers()
        collector.print_interesting_routers_summary()
        
        print(f"\n{'='*80}")
        print(f"Collection Complete!")
        print(f"{'='*80}")
        print(f"Total traceroutes: {len(results)}")
        print(f"Successful: {sum(1 for r in results if r.get('success'))}")
        print(f"Failed: {sum(1 for r in results if not r.get('success'))}")
        print(f"Summary: {summary_file}")
        print(f"CSV export: {csv_file}")
        print(f"Interesting routers JSON: {router_json}")
        print(f"Interesting routers TXT: {router_txt}")
        print(f"{'='*80}\n")
        
        # Run analysis
        print("Running analysis...")
        analyzer = TopologyAnalyzer(args.output_dir)
        analyzer.load_results(summary_file)
        report_file = analyzer.generate_report()
        print(f"Analysis report: {report_file}\n")


if __name__ == "__main__":
    main()
        
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
                "139.175.150.20", "203.133.1.8", "210.241.0.4", "139.175.1.1"
            ],
            "education_network": [
                "twaren.net", "tanet.edu.tw", "nchc.org.tw", "sinica.edu.tw"
            ]
        }
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.logger.debug(f"Reverse DNS: {ip} -> {hostname}")
            return hostname
        except (socket.herror, socket.gaierror):
            self.logger.debug(f"No reverse DNS for {ip}")
            return None
    
    def is_interesting_router(self, hostname: str) -> bool:
        """Check if hostname matches interesting patterns"""
        if not hostname:
            return False
        
        for pattern in self.interesting_patterns:
            if re.search(pattern, hostname, re.IGNORECASE):
                return True
        return False
    
    def add_interesting_router(self, ip: str, hostname: str, target: str, category: str):
        """Add a router to the interesting routers collection"""
        if ip not in self.interesting_routers:
            self.interesting_routers[ip] = {
                "hostname": hostname,
                "ip": ip,
                "appearances": 0,
                "targets": set(),
                "categories": set()
            }
        
        router = self.interesting_routers[ip]
        router["appearances"] += 1
        router["targets"].add(target)
        router["categories"].add(category)
    
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
        
        # Build traceroute command
        cmd = self._build_traceroute_cmd(ip, protocol, port, max_hops)
        
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
            
            # Parse output and collect interesting routers
            hops = self._parse_traceroute_output(
                result.stdout, 
                target, 
                metadata.get("category", "unknown") if metadata else "unknown"
            )
            
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
                             port: int, max_hops: int) -> List[str]:
        """Build traceroute command based on protocol"""
        base_cmd = ["traceroute", "-w", "3", "-q", "3", "-m", str(max_hops)]
        
        if protocol == "icmp":
            cmd = base_cmd + ["-I", ip]
        elif protocol == "udp":
            cmd = base_cmd + ["-p", str(port), ip]
        elif protocol == "tcp":
            cmd = base_cmd + ["-T", "-p", str(port), ip]
        else:
            cmd = base_cmd + [ip]
        
        return cmd
    
    def _parse_traceroute_output(self, output: str, target: str, category: str) -> List[Dict]:
        """Parse traceroute output into structured format and collect interesting routers"""
        hops = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip first line (header)
            hop = self._parse_hop_line(line, target, category)
            if hop:
                hops.append(hop)
        
        return hops
    
    def _parse_hop_line(self, line: str, target: str, category: str) -> Optional[Dict]:
        """Parse a single hop line from traceroute output and collect interesting routers"""
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
            
            # Check if we have hostname (parts[1]) or IP
            if '(' in line and ')' in line:
                # Format: "hostname (ip)"
                hostname_match = re.search(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)', line)
                if hostname_match:
                    hostname = hostname_match.group(1)
                    ip = hostname_match.group(2)
                else:
                    ip = parts[1]
                    hostname = self.reverse_dns_lookup(ip)
            else:
                # Only IP provided
                ip = parts[1]
                hostname = self.reverse_dns_lookup(ip)
            
            # Check if this is an interesting router
            if hostname and self.is_interesting_router(hostname):
                self.add_interesting_router(ip, hostname, target, category)
                self.logger.info(f"Found interesting router: {hostname} ({ip})")
            
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
    
    def save_interesting_routers(self):
        """Save interesting routers to JSON and text files"""
        # Convert sets to lists for JSON serialization
        routers_for_json = []
        for ip, data in self.interesting_routers.items():
            router_data = data.copy()
            router_data["targets"] = list(data["targets"])
            router_data["categories"] = list(data["categories"])
            routers_for_json.append(router_data)
        
        # Sort by appearances
        routers_for_json.sort(key=lambda x: x["appearances"], reverse=True)
        
        # Save JSON
        json_file = self.output_dir / f"interesting_routers_{self.timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                "timestamp": self.timestamp,
                "vantage_point": self.vantage_point,
                "total_routers": len(routers_for_json),
                "routers": routers_for_json
            }, f, indent=2)
        
        self.logger.info(f"Interesting routers JSON saved to {json_file}")
        
        # Save human-readable text file
        txt_file = self.output_dir / f"interesting_routers_{self.timestamp}.txt"
        with open(txt_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("INTERESTING ROUTERS DISCOVERED\n")
            f.write("=" * 80 + "\n")
            f.write(f"Collection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.vantage_point}\n")
            f.write(f"Total Interesting Routers: {len(routers_for_json)}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, router in enumerate(routers_for_json, 1):
                f.write(f"{i}. {router['hostname']}\n")
                f.write(f"   IP: {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique Targets: {len(router['targets'])}\n")
                f.write(f"   Categories: {', '.join(router['categories'])}\n")
                f.write(f"   Sample Targets: {', '.join(list(router['targets'])[:5])}\n")
                if len(router['targets']) > 5:
                    f.write(f"   ... and {len(router['targets']) - 5} more\n")
                f.write("\n")
        
        self.logger.info(f"Interesting routers text file saved to {txt_file}")
        
        return json_file, txt_file
    
    def print_interesting_routers_summary(self):
        """Print a summary of interesting routers to console"""
        if not self.interesting_routers:
            print("\nNo interesting routers found.")
            return
        
        # Convert and sort
        routers_list = []
        for ip, data in self.interesting_routers.items():
            routers_list.append({
                "ip": ip,
                "hostname": data["hostname"],
                "appearances": data["appearances"],
                "num_targets": len(data["targets"]),
                "categories": list(data["categories"])
            })
        
        routers_list.sort(key=lambda x: x["appearances"], reverse=True)
        
        print(f"\n{'='*80}")
        print(f"INTERESTING ROUTERS DISCOVERED: {len(routers_list)}")
        print(f"{'='*80}\n")
        
        # Print top 20
        for i, router in enumerate(routers_list[:20], 1):
            print(f"{i}. {router['hostname']}")
            print(f"   IP: {router['ip']}")
            print(f"   Appearances: {router['appearances']} | Unique Targets: {router['num_targets']}")
            print(f"   Categories: {', '.join(router['categories'])}")
            print()
        
        if len(routers_list) > 20:
            print(f"... and {len(routers_list) - 20} more routers")
            print(f"\nSee full list in the saved files.\n")
    
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
                "hop_num", "hop_ip", "hop_hostname", "hop_rtt_avg"
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
                        hop.get("avg_rtt", "")
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
    
    def find_core_routers(self, min_appearances: int = 10) -> List[Dict]:
        """Identify core routers that appear in many paths"""
        router_counts = defaultdict(lambda: {
            "count": 0,
            "targets": set(),
            "categories": set(),
            "hop_positions": []
        })
        
        for result in self.results:
            for hop in result["hops"]:
                if hop["ip"] and hop["ip"] != "*":
                    router_counts[hop["ip"]]["count"] += 1
                    router_counts[hop["ip"]]["targets"].add(result["target"])
                    router_counts[hop["ip"]]["categories"].add(result.get("category", "unknown"))
                    router_counts[hop["ip"]]["hop_positions"].append(hop["hop"])
        
        # Filter and sort
        core_routers = []
        for ip, data in router_counts.items():
            if data["count"] >= min_appearances:
                core_routers.append({
                    "ip": ip,
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
            f.write("=" * 80 + "\n\n")
            
            # Summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total traceroutes: {len(self.results)}\n")
            successful = sum(1 for r in self.results if r.get('success'))
            f.write(f"Successful: {successful} ({successful/len(self.results)*100:.1f}%)\n")
            f.write(f"Failed: {len(self.results) - successful}\n\n")
            
            # Service coverage analysis
            f.write("SERVICE COVERAGE ANALYSIS\n")
            f.write("-" * 80 + "\n")
            coverage = self.analyze_service_coverage()
            
            # Sort by success rate
            sorted_coverage = sorted(
                coverage.items(),
                key=lambda x: x[1]["success_rate"],
                reverse=True
            )
            
            for domain, data in sorted_coverage[:30]:  # Top 30
                f.write(f"\n{domain}\n")
                f.write(f"  Services tested: {data['num_services_tested']}\n")
                f.write(f"  Successful: {data['num_services_successful']}\n")
                f.write(f"  Success rate: {data['success_rate']}%\n")
                f.write(f"  Working services: {', '.join(data['successful_services']) or 'None'}\n")
            
            # Core routers
            f.write("\n\nCORE ROUTERS (appearing in 10+ paths)\n")
            f.write("-" * 80 + "\n")
            core_routers = self.find_core_routers(min_appearances=10)
            for i, router in enumerate(core_routers[:20], 1):
                f.write(f"{i}. {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique targets: {router['unique_targets']}\n")
                f.write(f"   Avg hop position: {router['avg_hop_position']}\n\n")
        
        self.logger.info(f"Analysis report saved to {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Taiwan ISP Topology Mapper - Enhanced Edition",
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
        
        # Save and print interesting routers
        router_json, router_txt = collector.save_interesting_routers()
        collector.print_interesting_routers_summary()
        
        print(f"\n{'='*80}")
        print(f"Collection Complete!")
        print(f"{'='*80}")
        print(f"Total traceroutes: {len(results)}")
        print(f"Successful: {sum(1 for r in results if r.get('success'))}")
        print(f"Failed: {sum(1 for r in results if not r.get('success'))}")
        print(f"Summary: {summary_file}")
        print(f"CSV export: {csv_file}")
        print(f"Interesting routers JSON: {router_json}")
        print(f"Interesting routers TXT: {router_txt}")
        print(f"{'='*80}\n")
        
        # Run analysis
        print("Running analysis...")
        analyzer = TopologyAnalyzer(args.output_dir)
        analyzer.load_results(summary_file)
        report_file = analyzer.generate_report()
        print(f"Analysis report: {report_file}\n")


if __name__ == "__main__":
    main()