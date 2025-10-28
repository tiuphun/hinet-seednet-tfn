#!/usr/bin/env python3
"""
Traceroute Data Analyzer and Report Generator
Reads JSON traceroute data and generates comprehensive TXT reports
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Set
import statistics


class TracerouteAnalyzer:
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.results = []
        self.interesting_routers = {}
        
    def load_summary_file(self, summary_file: str):
        """Load results from a summary JSON file"""
        with open(summary_file, 'r') as f:
            data = json.load(f)
            self.results = data.get("results", [])
            self.vantage_point = data.get("vantage_point", "unknown")
            self.collection_timestamp = data.get("collection_timestamp", "unknown")
        print(f"Loaded {len(self.results)} traceroute results from {summary_file}")
    
    def load_individual_files(self):
        """Load results from individual JSON files in raw/ directory"""
        raw_dir = self.data_dir / "raw"
        if not raw_dir.exists():
            print(f"Error: {raw_dir} does not exist")
            return
        
        json_files = list(raw_dir.glob("*.json"))
        print(f"Found {len(json_files)} JSON files to load...")
        
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    self.results.append(json.load(f))
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
        
        print(f"Loaded {len(self.results)} traceroute results")
    
    def extract_interesting_routers(self):
        """Extract and categorize interesting routers from traceroute data"""
        router_data = defaultdict(lambda: {
            "appearances": 0,
            "targets": set(),
            "categories": set(),
            "hop_positions": [],
            "avg_rtts": []
        })
        
        for result in self.results:
            target = result.get("target", "unknown")
            category = result.get("category", "unknown")
            
            for hop in result.get("hops", []):
                ip = hop.get("ip")
                hostname = hop.get("hostname")
                
                if ip and ip != "*":
                    router_data[ip]["appearances"] += 1
                    router_data[ip]["targets"].add(target)
                    router_data[ip]["categories"].add(category)
                    router_data[ip]["hop_positions"].append(hop.get("hop", 0))
                    
                    if hop.get("avg_rtt"):
                        router_data[ip]["avg_rtts"].append(hop["avg_rtt"])
                    
                    # Store hostname if available
                    if hostname and "hostname" not in router_data[ip]:
                        router_data[ip]["hostname"] = hostname
        
        # Convert sets to lists and calculate statistics
        for ip, data in router_data.items():
            data["targets"] = list(data["targets"])
            data["categories"] = list(data["categories"])
            data["num_targets"] = len(data["targets"])
            data["num_categories"] = len(data["categories"])
            
            if data["hop_positions"]:
                data["avg_hop_position"] = round(statistics.mean(data["hop_positions"]), 1)
                data["min_hop"] = min(data["hop_positions"])
                data["max_hop"] = max(data["hop_positions"])
            
            if data["avg_rtts"]:
                data["avg_rtt"] = round(statistics.mean(data["avg_rtts"]), 2)
                data["min_rtt"] = round(min(data["avg_rtts"]), 2)
                data["max_rtt"] = round(max(data["avg_rtts"]), 2)
        
        self.interesting_routers = router_data
        return router_data
    
    def generate_summary_report(self, output_file: str = None):
        """Generate a comprehensive summary report"""
        if not output_file:
            output_file = self.data_dir / f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            self._write_header(f)
            self._write_collection_summary(f)
            self._write_category_analysis(f)
            self._write_protocol_analysis(f)
            self._write_success_rate_analysis(f)
            self._write_service_discovery_analysis(f)
            self._write_path_length_analysis(f)
            self._write_latency_analysis(f)
            self._write_core_routers_analysis(f)
            self._write_interesting_routers_detailed(f)
        
        print(f"\nReport generated: {output_file}")
        return output_file
    
    def _write_header(self, f):
        """Write report header"""
        f.write("=" * 100 + "\n")
        f.write("TAIWAN ISP TOPOLOGY MAPPING - COMPREHENSIVE ANALYSIS REPORT\n")
        f.write("=" * 100 + "\n")
        f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Vantage Point: {getattr(self, 'vantage_point', 'unknown')}\n")
        f.write(f"Collection Timestamp: {getattr(self, 'collection_timestamp', 'unknown')}\n")
        f.write("=" * 100 + "\n\n")
    
    def _write_collection_summary(self, f):
        """Write overall collection summary"""
        f.write("COLLECTION SUMMARY\n")
        f.write("-" * 100 + "\n")
        
        total = len(self.results)
        successful = sum(1 for r in self.results if r.get("success"))
        failed = total - successful
        
        f.write(f"Total Traceroutes Executed: {total}\n")
        f.write(f"Successful: {successful} ({successful/total*100:.1f}%)\n")
        f.write(f"Failed: {failed} ({failed/total*100:.1f}%)\n")
        
        # Count unique targets
        unique_domains = len(set(r.get("base_domain", r.get("target")) for r in self.results))
        unique_ips = len(set(r.get("target_ip") for r in self.results if r.get("target_ip")))
        
        f.write(f"Unique Base Domains: {unique_domains}\n")
        f.write(f"Unique Target IPs: {unique_ips}\n")
        f.write("\n")
    
    def _write_category_analysis(self, f):
        """Write analysis by category"""
        f.write("ANALYSIS BY CATEGORY\n")
        f.write("-" * 100 + "\n")
        
        category_stats = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0})
        
        for result in self.results:
            cat = result.get("category", "unknown")
            category_stats[cat]["total"] += 1
            if result.get("success"):
                category_stats[cat]["success"] += 1
            else:
                category_stats[cat]["failed"] += 1
        
        # Sort by total count
        sorted_cats = sorted(category_stats.items(), key=lambda x: x[1]["total"], reverse=True)
        
        f.write(f"{'Category':<30} {'Total':<10} {'Success':<10} {'Failed':<10} {'Success Rate':<15}\n")
        f.write("-" * 100 + "\n")
        
        for cat, stats in sorted_cats:
            success_rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
            f.write(f"{cat:<30} {stats['total']:<10} {stats['success']:<10} {stats['failed']:<10} {success_rate:>6.1f}%\n")
        
        f.write("\n")
    
    def _write_protocol_analysis(self, f):
        """Write analysis by protocol"""
        f.write("ANALYSIS BY PROTOCOL\n")
        f.write("-" * 100 + "\n")
        
        protocol_stats = defaultdict(lambda: {"total": 0, "success": 0, "failed": 0})
        
        for result in self.results:
            proto = result.get("protocol", "unknown")
            port = result.get("port")
            key = f"{proto}-{port}" if port else proto
            
            protocol_stats[key]["total"] += 1
            if result.get("success"):
                protocol_stats[key]["success"] += 1
            else:
                protocol_stats[key]["failed"] += 1
        
        sorted_protos = sorted(protocol_stats.items(), key=lambda x: x[1]["total"], reverse=True)
        
        f.write(f"{'Protocol':<20} {'Total':<10} {'Success':<10} {'Failed':<10} {'Success Rate':<15}\n")
        f.write("-" * 100 + "\n")
        
        for proto, stats in sorted_protos:
            success_rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
            f.write(f"{proto:<20} {stats['total']:<10} {stats['success']:<10} {stats['failed']:<10} {success_rate:>6.1f}%\n")
        
        f.write("\n")
    
    def _write_success_rate_analysis(self, f):
        """Write detailed success rate analysis by domain"""
        f.write("DOMAIN SUCCESS RATE ANALYSIS (Top 30 by attempts)\n")
        f.write("-" * 100 + "\n")
        
        domain_stats = defaultdict(lambda: {"total": 0, "success": 0})
        
        for result in self.results:
            domain = result.get("base_domain", result.get("target"))
            domain_stats[domain]["total"] += 1
            if result.get("success"):
                domain_stats[domain]["success"] += 1
        
        # Sort by total attempts
        sorted_domains = sorted(domain_stats.items(), key=lambda x: x[1]["total"], reverse=True)
        
        f.write(f"{'Domain':<40} {'Attempts':<10} {'Success':<10} {'Success Rate':<15}\n")
        f.write("-" * 100 + "\n")
        
        for domain, stats in sorted_domains[:30]:
            success_rate = stats["success"] / stats["total"] * 100 if stats["total"] > 0 else 0
            f.write(f"{domain:<40} {stats['total']:<10} {stats['success']:<10} {success_rate:>6.1f}%\n")
        
        f.write("\n")
    
    def _write_service_discovery_analysis(self, f):
        """Write analysis of service discovery results"""
        f.write("SERVICE DISCOVERY ANALYSIS\n")
        f.write("-" * 100 + "\n")
        
        service_stats = defaultdict(lambda: {"domains": set(), "success": 0, "failed": 0})
        
        for result in self.results:
            base = result.get("base_domain", result.get("target"))
            variant = result.get("service_variant", result.get("target"))
            
            # Extract service prefix
            if variant != base and variant.endswith(base):
                prefix = variant.replace(f".{base}", "")
                service_stats[prefix]["domains"].add(base)
                if result.get("success"):
                    service_stats[prefix]["success"] += 1
                else:
                    service_stats[prefix]["failed"] += 1
        
        if service_stats:
            sorted_services = sorted(service_stats.items(), 
                                    key=lambda x: len(x[1]["domains"]), 
                                    reverse=True)
            
            f.write(f"{'Service Prefix':<20} {'Domains':<10} {'Success':<10} {'Failed':<10} {'Success Rate':<15}\n")
            f.write("-" * 100 + "\n")
            
            for prefix, stats in sorted_services[:20]:
                total = stats["success"] + stats["failed"]
                success_rate = stats["success"] / total * 100 if total > 0 else 0
                f.write(f"{prefix:<20} {len(stats['domains']):<10} {stats['success']:<10} {stats['failed']:<10} {success_rate:>6.1f}%\n")
        else:
            f.write("No service discovery data found (bare domains only)\n")
        
        f.write("\n")
    
    def _write_path_length_analysis(self, f):
        """Write analysis of path lengths"""
        f.write("PATH LENGTH ANALYSIS\n")
        f.write("-" * 100 + "\n")
        
        hop_counts = [r.get("num_hops", 0) for r in self.results if r.get("success")]
        
        if hop_counts:
            f.write(f"Average Hops: {statistics.mean(hop_counts):.1f}\n")
            f.write(f"Median Hops: {statistics.median(hop_counts):.1f}\n")
            f.write(f"Min Hops: {min(hop_counts)}\n")
            f.write(f"Max Hops: {max(hop_counts)}\n")
            f.write(f"Std Dev: {statistics.stdev(hop_counts):.2f}\n" if len(hop_counts) > 1 else "")
            
            # Hop distribution
            f.write("\nHop Count Distribution:\n")
            hop_dist = defaultdict(int)
            for hops in hop_counts:
                hop_dist[hops] += 1
            
            for hops in sorted(hop_dist.keys()):
                count = hop_dist[hops]
                bar = "█" * (count // 2)
                f.write(f"  {hops:2d} hops: {count:4d} {bar}\n")
        else:
            f.write("No successful traceroutes to analyze\n")
        
        f.write("\n")
    
    def _write_latency_analysis(self, f):
        """Write latency analysis"""
        f.write("LATENCY ANALYSIS\n")
        f.write("-" * 100 + "\n")
        
        # Collect final hop latencies
        final_rtts = []
        for result in self.results:
            if result.get("success"):
                hops = result.get("hops", [])
                if hops:
                    last_hop = hops[-1]
                    if last_hop.get("avg_rtt"):
                        final_rtts.append(last_hop["avg_rtt"])
        
        if final_rtts:
            f.write(f"Final Hop RTT Statistics (successful traces):\n")
            f.write(f"  Average: {statistics.mean(final_rtts):.2f} ms\n")
            f.write(f"  Median: {statistics.median(final_rtts):.2f} ms\n")
            f.write(f"  Min: {min(final_rtts):.2f} ms\n")
            f.write(f"  Max: {max(final_rtts):.2f} ms\n")
            f.write(f"  Std Dev: {statistics.stdev(final_rtts):.2f} ms\n" if len(final_rtts) > 1 else "")
        else:
            f.write("No latency data available\n")
        
        f.write("\n")
    
    def _write_core_routers_analysis(self, f):
        """Write analysis of core routers"""
        f.write("CORE ROUTERS ANALYSIS (appearing in 10+ paths)\n")
        f.write("-" * 100 + "\n")
        
        if not self.interesting_routers:
            self.extract_interesting_routers()
        
        # Filter core routers (appearing in many paths)
        core_routers = [
            (ip, data) for ip, data in self.interesting_routers.items()
            if data["appearances"] >= 10
        ]
        
        # Sort by appearances
        core_routers.sort(key=lambda x: x[1]["appearances"], reverse=True)
        
        if core_routers:
            f.write(f"Found {len(core_routers)} core routers\n\n")
            f.write(f"{'Rank':<6} {'IP Address':<18} {'Hostname':<45} {'Appearances':<12} {'Targets':<10}\n")
            f.write("-" * 100 + "\n")
            
            for i, (ip, data) in enumerate(core_routers[:30], 1):
                hostname = data.get("hostname", "No reverse DNS")[:43]
                f.write(f"{i:<6} {ip:<18} {hostname:<45} {data['appearances']:<12} {data['num_targets']:<10}\n")
        else:
            f.write("No core routers found (minimum 10 appearances)\n")
        
        f.write("\n")
    
    def _write_interesting_routers_detailed(self, f):
        """Write detailed analysis of interesting routers"""
        f.write("DETAILED ROUTER ANALYSIS (Top 50 by appearances)\n")
        f.write("=" * 100 + "\n\n")
        
        if not self.interesting_routers:
            self.extract_interesting_routers()
        
        # Sort by appearances
        sorted_routers = sorted(
            self.interesting_routers.items(),
            key=lambda x: x[1]["appearances"],
            reverse=True
        )
        
        for i, (ip, data) in enumerate(sorted_routers[:50], 1):
            f.write(f"{i}. {data.get('hostname', 'No reverse DNS')}\n")
            f.write(f"   IP Address: {ip}\n")
            f.write(f"   Appearances: {data['appearances']}\n")
            f.write(f"   Unique Targets: {data['num_targets']}\n")
            f.write(f"   Categories: {', '.join(data['categories'][:5])}")
            if len(data['categories']) > 5:
                f.write(f" (+{len(data['categories'])-5} more)")
            f.write("\n")
            
            if "avg_hop_position" in data:
                f.write(f"   Hop Position: avg={data['avg_hop_position']}, "
                       f"range={data['min_hop']}-{data['max_hop']}\n")
            
            if "avg_rtt" in data:
                f.write(f"   RTT: avg={data['avg_rtt']}ms, "
                       f"range={data['min_rtt']}-{data['max_rtt']}ms\n")
            
            f.write(f"   Sample Targets: {', '.join(data['targets'][:5])}")
            if len(data['targets']) > 5:
                f.write(f" (+{len(data['targets'])-5} more)")
            f.write("\n\n")
    
    def generate_failed_traces_report(self, output_file: str = None):
        """Generate a report focusing on failed traceroutes"""
        if not output_file:
            output_file = self.data_dir / f"failed_traces_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        failed = [r for r in self.results if not r.get("success")]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 100 + "\n")
            f.write("FAILED TRACEROUTES ANALYSIS\n")
            f.write("=" * 100 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Failed Traces: {len(failed)}\n")
            f.write("=" * 100 + "\n\n")
            
            # Group by domain
            failed_by_domain = defaultdict(list)
            for result in failed:
                domain = result.get("base_domain", result.get("target"))
                failed_by_domain[domain].append(result)
            
            f.write("FAILED TRACES BY DOMAIN\n")
            f.write("-" * 100 + "\n")
            
            sorted_domains = sorted(failed_by_domain.items(), 
                                   key=lambda x: len(x[1]), 
                                   reverse=True)
            
            for domain, results in sorted_domains:
                f.write(f"\n{domain} ({len(results)} failed attempts)\n")
                f.write("-" * 80 + "\n")
                
                for result in results:
                    protocol = result.get("protocol", "unknown")
                    port = result.get("port")
                    proto_str = f"{protocol}-{port}" if port else protocol
                    variant = result.get("service_variant", domain)
                    f.write(f"  • {variant} via {proto_str}\n")
                    
                    # Show how far it got
                    hops = result.get("hops", [])
                    valid_hops = [h for h in hops if not h.get("timeout")]
                    if valid_hops:
                        last_hop = valid_hops[-1]
                        f.write(f"    Last valid hop: {last_hop.get('hop')} - "
                               f"{last_hop.get('hostname') or last_hop.get('ip', 'unknown')}\n")
                    else:
                        f.write(f"    No valid hops received\n")
        
        print(f"\nFailed traces report generated: {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Traceroute Data Analyzer - Generate TXT reports from JSON data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze from summary JSON file
  python3 analyzer.py --summary traceroute_data/summary_20241022_101530.json
  
  # Analyze from individual JSON files in raw/ directory
  python3 analyzer.py --data-dir traceroute_data
  
  # Generate both summary and failed traces reports
  python3 analyzer.py --summary traceroute_data/summary_*.json --failed-report
        """
    )
    
    parser.add_argument("--summary", help="Path to summary JSON file")
    parser.add_argument("--data-dir", default="traceroute_data",
                       help="Directory containing raw JSON files")
    parser.add_argument("--output", help="Output file path for main report")
    parser.add_argument("--failed-report", action="store_true",
                       help="Also generate a report for failed traceroutes")
    
    args = parser.parse_args()
    
    analyzer = TracerouteAnalyzer(args.data_dir)
    
    # Load data
    if args.summary:
        analyzer.load_summary_file(args.summary)
    else:
        analyzer.load_individual_files()
    
    if not analyzer.results:
        print("Error: No data loaded. Specify --summary file or --data-dir with raw/ subfolder")
        return
    
    # Generate main report
    print("\nGenerating comprehensive analysis report...")
    report_file = analyzer.generate_summary_report(args.output)
    print(f"✓ Main report: {report_file}")
    
    # Generate failed traces report if requested
    if args.failed_report:
        print("\nGenerating failed traces report...")
        failed_file = analyzer.generate_failed_traces_report()
        print(f"✓ Failed traces report: {failed_file}")
    
    print("\nAnalysis complete!")


if __name__ == "__main__":
    main()