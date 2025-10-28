#!/usr/bin/env python3
"""
Taiwan ISP Topology Mapping - Scapy Enhanced Traceroute Collection System
Research: HiNet (AS3462), SEEDnet (AS4780), Taiwan Fixed Network (AS9924)

Enhanced Features with Scapy:
- Custom packet crafting for better success rates
- Multiple probe types (ICMP, TCP SYN, UDP)
- Handles ICMP TTL exceeded and destination unreachable responses
- More reliable hop detection
- Timeout and retry handling
"""

import json
import csv
import time
import socket
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
import argparse
import logging
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.inet import IP, ICMP, TCP, UDP
except ImportError:
    print("Error: Scapy is required. Install with: pip install scapy")
    print("Note: May require sudo/root privileges to run")
    exit(1)

# Suppress Scapy warnings
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
conf.verb = 0  # Suppress Scapy output


class ScapyTracerouteCollector:
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
            "", "www", "www2", "mail", "smtp", "ftp", "ns", "ns1", "ns2",
            "api", "app", "portal", "webmail", "vpn", "remote"
        ]
        
        # Interesting router collection
        self.interesting_routers = {}
        self.collect_all_named_routers = True
        
        # Patterns for highlighting interesting routers
        self.interesting_patterns = [
            r'hinet\.net', r'seednet\.net', r'so-net\.net', r'fixednet\.tw',
            r'tfn\.net\.tw', r'fxn\.tw', r'\.gov\.tw', r'\.edu\.tw',
            r'tanet\.edu\.tw', r'twaren\.net', r'cht\.com\.tw', r'fetnet\.net',
            r'taiwanmobile\.com', r'aptg\.com\.tw', r'chief\.com\.tw',
            r'tpix\.net', r'\.tw', r'\.com\.tw', r'\.net\.tw'
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
            return hostname
        except (socket.herror, socket.gaierror):
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
    
    def resolve_target(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(target)
            self.logger.debug(f"Resolved {target} -> {ip}")
            return ip
        except socket.gaierror:
            self.logger.debug(f"Failed to resolve {target}")
            return None
    
    def scapy_traceroute_icmp(self, dst_ip: str, max_hops: int = 30, 
                              timeout: float = 2.0, retry: int = 3) -> List[Dict]:
        """
        Perform traceroute using ICMP Echo Request packets
        More reliable than standard traceroute
        """
        hops = []
        
        for ttl in range(1, max_hops + 1):
            hop_info = {
                "hop": ttl,
                "ip": None,
                "hostname": None,
                "rtts": [],
                "timeout": True
            }
            
            # Send multiple probes per hop
            for _ in range(retry):
                # Craft ICMP packet with specific TTL
                pkt = IP(dst=dst_ip, ttl=ttl) / ICMP()
                
                # Send and wait for response
                start_time = time.time()
                reply = sr1(pkt, timeout=timeout, verbose=0)
                rtt = (time.time() - start_time) * 1000  # Convert to ms
                
                if reply is not None:
                    hop_info["timeout"] = False
                    hop_info["ip"] = reply.src
                    hop_info["rtts"].append(round(rtt, 2))
                    
                    # Check if we reached destination
                    if reply.src == dst_ip and reply.type == 0:  # ICMP Echo Reply
                        if not hop_info["hostname"]:
                            hop_info["hostname"] = self.reverse_dns_lookup(reply.src)
                        hop_info["reached_destination"] = True
            
            # Calculate average RTT if we got responses
            if hop_info["rtts"]:
                hop_info["avg_rtt"] = round(sum(hop_info["rtts"]) / len(hop_info["rtts"]), 2)
                if not hop_info["hostname"]:
                    hop_info["hostname"] = self.reverse_dns_lookup(hop_info["ip"])
            
            hops.append(hop_info)
            
            # Stop if we reached destination
            if hop_info.get("reached_destination"):
                break
        
        return hops
    
    def scapy_traceroute_tcp(self, dst_ip: str, dst_port: int = 80, 
                            max_hops: int = 30, timeout: float = 2.0, 
                            retry: int = 3) -> List[Dict]:
        """
        Perform traceroute using TCP SYN packets
        Often more successful than ICMP as it mimics real traffic
        """
        hops = []
        
        for ttl in range(1, max_hops + 1):
            hop_info = {
                "hop": ttl,
                "ip": None,
                "hostname": None,
                "rtts": [],
                "timeout": True
            }
            
            for _ in range(retry):
                # Craft TCP SYN packet with specific TTL
                pkt = IP(dst=dst_ip, ttl=ttl) / TCP(dport=dst_port, flags="S")
                
                start_time = time.time()
                reply = sr1(pkt, timeout=timeout, verbose=0)
                rtt = (time.time() - start_time) * 1000
                
                if reply is not None:
                    hop_info["timeout"] = False
                    hop_info["ip"] = reply.src
                    hop_info["rtts"].append(round(rtt, 2))
                    
                    # Check if we got SYN-ACK or RST from destination
                    if reply.src == dst_ip:
                        if TCP in reply and (reply[TCP].flags & 0x12 or reply[TCP].flags & 0x04):
                            hop_info["reached_destination"] = True
            
            if hop_info["rtts"]:
                hop_info["avg_rtt"] = round(sum(hop_info["rtts"]) / len(hop_info["rtts"]), 2)
                if not hop_info["hostname"]:
                    hop_info["hostname"] = self.reverse_dns_lookup(hop_info["ip"])
            
            hops.append(hop_info)
            
            if hop_info.get("reached_destination"):
                break
        
        return hops
    
    def scapy_traceroute_udp(self, dst_ip: str, dst_port: int = 53, 
                            max_hops: int = 30, timeout: float = 2.0, 
                            retry: int = 3) -> List[Dict]:
        """
        Perform traceroute using UDP packets
        Useful for targeting specific services like DNS
        """
        hops = []
        
        for ttl in range(1, max_hops + 1):
            hop_info = {
                "hop": ttl,
                "ip": None,
                "hostname": None,
                "rtts": [],
                "timeout": True
            }
            
            for _ in range(retry):
                # Craft UDP packet with specific TTL
                pkt = IP(dst=dst_ip, ttl=ttl) / UDP(dport=dst_port)
                
                start_time = time.time()
                reply = sr1(pkt, timeout=timeout, verbose=0)
                rtt = (time.time() - start_time) * 1000
                
                if reply is not None:
                    hop_info["timeout"] = False
                    hop_info["ip"] = reply.src
                    hop_info["rtts"].append(round(rtt, 2))
                    
                    # Check for ICMP Port Unreachable (destination reached)
                    if reply.src == dst_ip and ICMP in reply and reply[ICMP].type == 3:
                        hop_info["reached_destination"] = True
            
            if hop_info["rtts"]:
                hop_info["avg_rtt"] = round(sum(hop_info["rtts"]) / len(hop_info["rtts"]), 2)
                if not hop_info["hostname"]:
                    hop_info["hostname"] = self.reverse_dns_lookup(hop_info["ip"])
            
            hops.append(hop_info)
            
            if hop_info.get("reached_destination"):
                break
        
        return hops
    
    def run_traceroute(self, target: str, protocol: str = "icmp", 
                      port: int = 80, max_hops: int = 30,
                      metadata: Dict = None) -> Optional[Dict]:
        """Run a single traceroute with specified protocol using Scapy"""
        
        # Resolve target
        ip = self.resolve_target(target) if not self._is_ip(target) else target
        if not ip:
            return None
        
        self.logger.info(f"Tracing {target} ({ip}) via {protocol.upper()}")
        
        try:
            start_time = time.time()
            
            # Choose traceroute method based on protocol
            if protocol == "icmp":
                hops = self.scapy_traceroute_icmp(ip, max_hops)
            elif protocol == "tcp":
                hops = self.scapy_traceroute_tcp(ip, port, max_hops)
            elif protocol == "udp":
                hops = self.scapy_traceroute_udp(ip, port, max_hops)
            else:
                self.logger.error(f"Unknown protocol: {protocol}")
                return None
            
            duration = time.time() - start_time
            
            # Collect interesting routers
            category = metadata.get("category", "unknown") if metadata else "unknown"
            for hop in hops:
                if hop["ip"] and hop["hostname"]:
                    if self.is_interesting_router(hop["hostname"]):
                        self.add_interesting_router(hop["ip"], hop["hostname"], 
                                                   target, category)
            
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
                "success": any(h.get("reached_destination") for h in hops),
                "method": "scapy"
            }
            
            if metadata:
                trace_result.update(metadata)
            
            return trace_result
            
        except Exception as e:
            self.logger.error(f"Error running traceroute to {target}: {e}")
            return None
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(pattern, target))
    
    def discover_reachable_services(self, domain: str, 
                                   quick_check: bool = True) -> List[Dict]:
        """Discover which service variants are reachable for a domain"""
        reachable = []
        
        if quick_check:
            # Quick mode: just test bare domain and www
            ip = self.resolve_target(domain)
            if ip:
                reachable.append({
                    "variant": domain,
                    "ip": ip,
                    "is_bare_domain": True,
                    "reachable": True
                })
                
                # Also test www variant
                www_variant = f"www.{domain}"
                www_ip = self.resolve_target(www_variant)
                if www_ip and www_ip != ip:
                    reachable.append({
                        "variant": www_variant,
                        "ip": www_ip,
                        "is_bare_domain": False,
                        "reachable": True
                    })
        else:
            # Full mode: test all service prefixes
            # First add bare domain
            ip = self.resolve_target(domain)
            if ip:
                reachable.append({
                    "variant": domain,
                    "ip": ip,
                    "is_bare_domain": True,
                    "reachable": True
                })
            
            # Test all prefixed variants
            for prefix in self.service_prefixes:
                if prefix:  # Skip empty prefix (already tested as bare domain)
                    variant = f"{prefix}.{domain}"
                    variant_ip = self.resolve_target(variant)
                    if variant_ip:
                        reachable.append({
                            "variant": variant,
                            "ip": variant_ip,
                            "is_bare_domain": False,
                            "reachable": True
                        })
        
        if not reachable:
            self.logger.warning(f"No reachable services found for {domain}")
        else:
            self.logger.info(f"Found {len(reachable)} reachable service(s) for {domain}")
        
        return reachable
    
    def collect_batch(self, category: str = None, protocols: List[str] = None,
                     delay: float = 0.5, service_discovery: bool = True,
                     max_services_per_domain: int = 2) -> List[Dict]:
        """Collect traceroutes for a batch of targets"""
        
        if protocols is None:
            protocols = ["icmp", "tcp-80", "tcp-443"]
        
        results = []
        tested_ips = set()
        
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
                
                # Discover reachable services
                if service_discovery and not self._is_ip(domain):
                    # Use quick_check based on max_services setting
                    quick_check = (max_services_per_domain <= 2)
                    services = self.discover_reachable_services(
                        domain, 
                        quick_check=quick_check
                    )
                    # Limit number of services to test
                    services = services[:max_services_per_domain]
                else:
                    # Just test the domain/IP itself
                    ip = self.resolve_target(domain) if not self._is_ip(domain) else domain
                    services = [{
                        "variant": domain,
                        "ip": ip,
                        "is_bare_domain": True,
                        "reachable": True
                    }] if ip else []
                
                # If no services found, log warning and skip
                if not services:
                    self.logger.warning(f"Skipping {domain} - no reachable services")
                    continue
                
                # Test each service with each protocol
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
                        
                        test_key = f"{target_ip}:{protocol}:{port}"
                        
                        if test_key in tested_ips:
                            self.logger.debug(f"Skipping duplicate: {test_key}")
                            continue
                        
                        tested_ips.add(test_key)
                        
                        metadata = {
                            "category": cat,
                            "base_domain": domain,
                            "service_variant": target,
                            "is_bare_domain": service.get("is_bare_domain", False)
                        }
                        
                        result = self.run_traceroute(target, protocol, port, metadata=metadata)
                        
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
            "method": "scapy",
            "results": results
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Summary saved to {summary_file}")
        return summary_file
    
    def save_interesting_routers(self):
        """Save interesting routers to JSON and text files"""
        routers_for_json = []
        for ip, data in self.interesting_routers.items():
            router_data = data.copy()
            router_data["targets"] = list(data["targets"])
            router_data["categories"] = list(data["categories"])
            routers_for_json.append(router_data)
        
        routers_for_json.sort(key=lambda x: x["appearances"], reverse=True)
        
        json_file = self.output_dir / f"interesting_routers_{self.timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                "timestamp": self.timestamp,
                "vantage_point": self.vantage_point,
                "total_routers": len(routers_for_json),
                "routers": routers_for_json
            }, f, indent=2)
        
        return json_file
    
    def export_to_csv(self, results: List[Dict]):
        """Export results to CSV format"""
        csv_file = self.output_dir / f"traceroutes_{self.timestamp}.csv"
        
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "vantage_point", "category", "base_domain",
                "service_variant", "target_ip", "protocol", "port",
                "num_hops", "success", "duration_seconds",
                "hop_num", "hop_ip", "hop_hostname", "hop_rtt_avg"
            ])
            
            for result in results:
                base_row = [
                    result["timestamp"], result["vantage_point"],
                    result.get("category", ""), result.get("base_domain", result["target"]),
                    result.get("service_variant", result["target"]), result["target_ip"],
                    result["protocol"], result.get("port", ""),
                    result["num_hops"], result["success"], result["duration_seconds"]
                ]
                
                for hop in result["hops"]:
                    row = base_row + [
                        hop["hop"], hop["ip"] or "*",
                        hop.get("hostname", ""), hop.get("avg_rtt", "")
                    ]
                    writer.writerow(row)
        
        return csv_file


def main():
    parser = argparse.ArgumentParser(
        description="Taiwan ISP Topology Mapper - Scapy Enhanced",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--vantage-point", required=True,
                       help="Vantage point identifier")
    parser.add_argument("--category",
                       help="Specific category to trace")
    parser.add_argument("--protocols", nargs="+",
                       default=["icmp", "tcp-80", "tcp-443"],
                       help="Protocols (icmp, tcp-PORT, udp-PORT)")
    parser.add_argument("--output-dir", default="traceroute_data",
                       help="Output directory")
    parser.add_argument("--delay", type=float, default=0.5,
                       help="Delay between traceroutes (seconds)")
    parser.add_argument("--max-services", type=int, default=2,
                       help="Max service variants per domain")
    parser.add_argument("--no-service-discovery", action="store_true",
                       help="Disable service discovery (test only bare domains)")
    
    args = parser.parse_args()
    
    # Check for root/sudo
    if os.geteuid() != 0:
        print("Warning: This script requires root/sudo privileges for raw socket access")
        print("Run with: sudo python3 script.py ...")
        exit(1)
    
    collector = ScapyTracerouteCollector(
        output_dir=args.output_dir,
        vantage_point=args.vantage_point
    )
    
    print(f"\n{'='*80}")
    print(f"Taiwan ISP Topology Mapping - Scapy Enhanced")
    print(f"{'='*80}")
    print(f"Vantage Point: {args.vantage_point}")
    print(f"Category: {args.category or 'ALL'}")
    print(f"Protocols: {', '.join(args.protocols)}")
    print(f"Service Discovery: {'Disabled' if args.no_service_discovery else 'Enabled'}")
    if not args.no_service_discovery:
        print(f"Max Services/Domain: {args.max_services}")
    print(f"Output: {args.output_dir}")
    print(f"{'='*80}\n")
    
    results = collector.collect_batch(
        category=args.category,
        protocols=args.protocols,
        delay=args.delay,
        service_discovery=not args.no_service_discovery,
        max_services_per_domain=args.max_services
    )
    
    summary_file = collector.save_summary(results)
    csv_file = collector.export_to_csv(results)
    router_file = collector.save_interesting_routers()
    
    print(f"\n{'='*80}")
    print(f"Collection Complete!")
    print(f"{'='*80}")
    print(f"Total: {len(results)}")
    print(f"Successful: {sum(1 for r in results if r.get('success'))}")
    print(f"Summary: {summary_file}")
    print(f"CSV: {csv_file}")
    print(f"Routers: {router_file}")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    main()