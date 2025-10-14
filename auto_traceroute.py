#!/usr/bin/env python3
"""
Taiwan ISP Topology Mapping - Automated Traceroute Collection System
Research: HiNet (AS3462), SEEDnet (AS4780), Taiwan Fixed Network (AS9924)
"""

import subprocess
import json
import csv
import time
import socket
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
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
    
    def resolve_target(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(target)
            self.logger.info(f"Resolved {target} -> {ip}")
            return ip
        except socket.gaierror:
            self.logger.warning(f"Failed to resolve {target}")
            return None
    
    def run_traceroute(self, target: str, protocol: str = "icmp", 
                       port: int = 80, max_hops: int = 30) -> Optional[Dict]:
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
            
            # Parse output
            hops = self._parse_traceroute_output(result.stdout)
            
            return {
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
        # Pattern: hop_num  ip  rtt1 ms  rtt2 ms  rtt3 ms
        # Or:      hop_num  * * *
        
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
                "hostname": None,  # We use -n flag, so no hostname
                "rtts": rtts,
                "avg_rtt": round(sum(rtts) / len(rtts), 2) if rtts else None,
                "timeout": False
            }
            
        except (ValueError, IndexError):
            return None
    
    def collect_batch(self, category: str = None, protocols: List[str] = None,
                     delay: float = 1.0) -> List[Dict]:
        """Collect traceroutes for a batch of targets"""
        
        if protocols is None:
            protocols = ["icmp", "tcp-80", "tcp-443"]
        
        results = []
        
        # Select targets
        if category and category in self.targets:
            targets_dict = {category: self.targets[category]}
        else:
            targets_dict = self.targets
        
        total_targets = sum(len(targets) for targets in targets_dict.values())
        current = 0
        
        for cat, targets in targets_dict.items():
            self.logger.info(f"Processing category: {cat}")
            
            for target in targets:
                current += 1
                self.logger.info(f"Progress: {current}/{total_targets} - {target}")
                
                for protocol_spec in protocols:
                    # Parse protocol specification
                    if '-' in protocol_spec:
                        protocol, port = protocol_spec.split('-')
                        port = int(port)
                    else:
                        protocol = protocol_spec
                        port = 80
                    
                    result = self.run_traceroute(target, protocol, port)
                    
                    if result:
                        result["category"] = cat
                        results.append(result)
                        self._save_result(result)
                    
                    time.sleep(delay)  # Rate limiting
        
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
            "results": results
        }
        
        for result in results:
            summary["categories"][result.get("category", "unknown")] += 1
            summary["protocols"][result.get("protocol", "unknown")] += 1
        
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
                "timestamp", "vantage_point", "category", "target", "target_ip",
                "protocol", "port", "num_hops", "success", "duration_seconds",
                "hop_num", "hop_ip", "hop_rtt_avg"
            ])
            
            # Data rows - one per hop
            for result in results:
                base_row = [
                    result["timestamp"],
                    result["vantage_point"],
                    result.get("category", ""),
                    result["target"],
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
    
    def identify_as_borders(self) -> List[Dict]:
        """Identify potential AS border routers (where AS changes)"""
        # This requires AS lookup - placeholder for now
        self.logger.info("AS border identification requires external AS lookup data")
        return []
    
    def find_path_diversity(self, target: str) -> Dict:
        """Analyze path diversity for a specific target"""
        target_results = [r for r in self.results if r["target"] == target]
        
        if not target_results:
            return {"error": f"No results found for {target}"}
        
        paths = {}
        for result in target_results:
            path_key = tuple(hop["ip"] for hop in result["hops"] if hop["ip"])
            if path_key not in paths:
                paths[path_key] = []
            paths[path_key].append(result)
        
        return {
            "target": target,
            "total_measurements": len(target_results),
            "unique_paths": len(paths),
            "paths": [
                {
                    "path": list(path),
                    "occurrences": len(results),
                    "protocols": list(set(r["protocol"] for r in results))
                }
                for path, results in paths.items()
            ]
        }
    
    def generate_report(self, output_file: str = None):
        """Generate comprehensive analysis report"""
        if not output_file:
            output_file = self.data_dir / f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("TAIWAN ISP TOPOLOGY MAPPING - ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total traceroutes: {len(self.results)}\n")
            f.write(f"Successful: {sum(1 for r in self.results if r.get('success'))}\n")
            f.write(f"Failed: {sum(1 for r in self.results if not r.get('success'))}\n\n")
            
            # Core routers
            f.write("CORE ROUTERS (appearing in 10+ paths)\n")
            f.write("-" * 80 + "\n")
            core_routers = self.find_core_routers(min_appearances=10)
            for i, router in enumerate(core_routers[:20], 1):  # Top 20
                f.write(f"{i}. {router['ip']}\n")
                f.write(f"   Appearances: {router['appearances']}\n")
                f.write(f"   Unique targets: {router['unique_targets']}\n")
                f.write(f"   Avg hop position: {router['avg_hop_position']}\n")
                f.write(f"   Categories: {', '.join(router['categories'])}\n\n")
        
        self.logger.info(f"Analysis report saved to {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(description="Taiwan ISP Topology Mapper")
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
        print(f"Taiwan ISP Topology Mapping - Data Collection")
        print(f"{'='*80}")
        print(f"Vantage Point: {args.vantage_point}")
        print(f"Category: {args.category or 'ALL'}")
        print(f"Protocols: {', '.join(args.protocols)}")
        print(f"Output Directory: {args.output_dir}")
        print(f"{'='*80}\n")
        
        # Collect data
        results = collector.collect_batch(
            category=args.category,
            protocols=args.protocols,
            delay=args.delay
        )
        
        # Save summary and export
        summary_file = collector.save_summary(results)
        csv_file = collector.export_to_csv(results)
        
        print(f"\n{'='*80}")
        print(f"Collection Complete!")
        print(f"{'='*80}")
        print(f"Total traceroutes: {len(results)}")
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