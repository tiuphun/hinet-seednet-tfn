#!/usr/bin/env python3
"""
Taiwan ISP Topology - Advanced Analysis and Visualization Tools
"""

import json
import csv
from pathlib import Path
from collections import defaultdict, Counter
from typing import List, Dict, Set, Tuple
import subprocess
import re

class ASNLookup:
    """Lookup ASN information for IP addresses"""
    
    def __init__(self, cache_file: str = "asn_cache.json"):
        self.cache_file = Path(cache_file)
        self.cache = self._load_cache()
    
    def _load_cache(self) -> Dict:
        """Load cached ASN lookups"""
        if self.cache_file.exists():
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_cache(self):
        """Save ASN cache"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def lookup_ip(self, ip: str) -> Dict:
        """Lookup ASN for an IP address using whois"""
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            result = subprocess.run(
                ["whois", "-h", "whois.cymru.com", ip],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Parse Team Cymru response
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                parts = lines[1].split('|')
                if len(parts) >= 3:
                    asn = parts[0].strip()
                    prefix = parts[1].strip()
                    country = parts[2].strip()
                    
                    info = {
                        "asn": asn,
                        "prefix": prefix,
                        "country": country,
                        "description": parts[4].strip() if len(parts) > 4 else ""
                    }
                    
                    self.cache[ip] = info
                    self._save_cache()
                    return info
            
            return {"asn": "Unknown", "prefix": "", "country": "", "description": ""}
            
        except Exception as e:
            print(f"Error looking up {ip}: {e}")
            return {"asn": "Error", "prefix": "", "country": "", "description": ""}
    
    def bulk_lookup(self, ips: List[str], delay: float = 0.5):
        """Lookup multiple IPs with rate limiting"""
        import time
        results = {}
        for ip in ips:
            if ip and ip != "*":
                results[ip] = self.lookup_ip(ip)
                time.sleep(delay)
        return results


class PathAnalyzer:
    """Analyze path characteristics and routing behavior"""
    
    def __init__(self, results: List[Dict]):
        self.results = results
        self.asn_lookup = ASNLookup()
    
    def find_as_paths(self) -> List[Dict]:
        """Extract AS-level paths from IP-level traceroutes"""
        as_paths = []
        
        for result in self.results:
            # Get IPs from hops
            ips = [hop["ip"] for hop in result["hops"] if hop["ip"] and hop["ip"] != "*"]
            
            # Lookup ASNs
            as_sequence = []
            prev_asn = None
            
            for ip in ips:
                asn_info = self.asn_lookup.lookup_ip(ip)
                asn = asn_info.get("asn", "Unknown")
                
                # Only add if ASN changes (collapse consecutive same ASN)
                if asn != prev_asn:
                    as_sequence.append({
                        "asn": asn,
                        "ip": ip,
                        "description": asn_info.get("description", "")
                    })
                    prev_asn = asn
            
            as_paths.append({
                "target": result["target"],
                "target_ip": result["target_ip"],
                "timestamp": result["timestamp"],
                "as_path": as_sequence,
                "as_path_length": len(as_sequence)
            })
        
        return as_paths
    
    def identify_as_borders(self, as_paths: List[Dict]) -> List[Dict]:
        """Identify AS border crossings"""
        borders = []
        
        for path_info in as_paths:
            as_path = path_info["as_path"]
            
            for i in range(len(as_path) - 1):
                from_as = as_path[i]
                to_as = as_path[i + 1]
                
                if from_as["asn"] != to_as["asn"]:
                    borders.append({
                        "target": path_info["target"],
                        "from_asn": from_as["asn"],
                        "from_ip": from_as["ip"],
                        "from_org": from_as["description"],
                        "to_asn": to_as["asn"],
                        "to_ip": to_as["ip"],
                        "to_org": to_as["description"],
                        "hop_position": i + 1
                    })
        
        return borders
    
    def find_peering_points(self, borders: List[Dict]) -> Dict:
        """Identify common peering points between ASes"""
        peering_counts = defaultdict(lambda: {
            "count": 0,
            "targets": set(),
            "ips": set()
        })
        
        for border in borders:
            key = f"{border['from_asn']} -> {border['to_asn']}"
            peering_counts[key]["count"] += 1
            peering_counts[key]["targets"].add(border["target"])
            peering_counts[key]["ips"].add(f"{border['from_ip']} -> {border['to_ip']}")
        
        # Convert to list and sort
        peering_list = []
        for key, data in peering_counts.items():
            from_asn, to_asn = key.split(" -> ")
            peering_list.append({
                "from_asn": from_asn,
                "to_asn": to_asn,
                "occurrences": data["count"],
                "unique_targets": len(data["targets"]),
                "unique_ip_pairs": len(data["ips"])
            })
        
        peering_list.sort(key=lambda x: x["occurrences"], reverse=True)
        return {"peerings": peering_list, "total_unique_peerings": len(peering_list)}
    
    def detect_load_balancing(self) -> List[Dict]:
        """Detect load balancing by finding multiple paths to same target"""
        target_paths = defaultdict(list)
        
        for result in self.results:
            path_signature = tuple(hop["ip"] for hop in result["hops"] if hop["ip"])
            target_paths[result["target"]].append({
                "path": path_signature,
                "timestamp": result["timestamp"],
                "protocol": result["protocol"]
            })
        
        load_balanced = []
        for target, paths in target_paths.items():
            unique_paths = {}
            for path_info in paths:
                path_key = path_info["path"]
                if path_key not in unique_paths:
                    unique_paths[path_key] = []
                unique_paths[path_key].append(path_info)
            
            if len(unique_paths) > 1:
                load_balanced.append({
                    "target": target,
                    "unique_paths": len(unique_paths),
                    "total_measurements": len(paths),
                    "paths_detail": [
                        {
                            "path": list(path),
                            "occurrences": len(occurrences)
                        }
                        for path, occurrences in unique_paths.items()
                    ]
                })
        
        return load_balanced
    
    def analyze_latency_patterns(self) -> Dict:
        """Analyze latency patterns across hops"""
        hop_latencies = defaultdict(list)
        
        for result in self.results:
            for hop in result["hops"]:
                if hop.get("avg_rtt"):
                    hop_latencies[hop["hop"]].append(hop["avg_rtt"])
        
        stats = {}
        for hop_num, rtts in sorted(hop_latencies.items()):
            stats[hop_num] = {
                "min": min(rtts),
                "max": max(rtts),
                "avg": sum(rtts) / len(rtts),
                "count": len(rtts)
            }
        
        return stats


class TopologyGraphGenerator:
    """Generate network topology graphs for visualization"""
    
    def __init__(self, results: List[Dict]):
        self.results = results
        self.nodes = set()
        self.edges = defaultdict(lambda: {"count": 0, "targets": set()})
    
    def build_graph(self):
        """Build graph from traceroute results"""
        for result in self.results:
            prev_ip = "SOURCE"
            self.nodes.add(prev_ip)
            
            for hop in result["hops"]:
                if hop["ip"] and hop["ip"] != "*":
                    current_ip = hop["ip"]
                    self.nodes.add(current_ip)
                    
                    edge_key = (prev_ip, current_ip)
                    self.edges[edge_key]["count"] += 1
                    self.edges[edge_key]["targets"].add(result["target"])
                    
                    prev_ip = current_ip
            
            # Add edge to target
            if result.get("success") and prev_ip != "SOURCE":
                edge_key = (prev_ip, result["target_ip"])
                self.edges[edge_key]["count"] += 1
                self.edges[edge_key]["targets"].add(result["target"])
                self.nodes.add(result["target_ip"])
    
    def export_graphviz(self, output_file: str, min_edge_weight: int = 2):
        """Export graph in Graphviz DOT format"""
        with open(output_file, 'w') as f:
            f.write("digraph ISPTopology {\n")
            f.write("  rankdir=LR;\n")
            f.write("  node [shape=box, style=filled, fillcolor=lightblue];\n\n")
            
            # Write edges with weights
            for (from_ip, to_ip), data in self.edges.items():
                if data["count"] >= min_edge_weight:
                    weight = data["count"]
                    width = min(1 + (weight / 10), 5)
                    f.write(f'  "{from_ip}" -> "{to_ip}" [label="{weight}", penwidth={width:.1f}];\n')
            
            f.write("}\n")
        
        print(f"Graphviz DOT file exported to {output_file}")
        print(f"Generate visualization with: dot -Tpng {output_file} -o topology.png")
    
    def export_gephi(self, output_file: str):
        """Export graph in Gephi-compatible CSV format"""
        # Nodes file
        nodes_file = output_file.replace('.csv', '_nodes.csv')
        with open(nodes_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Id', 'Label'])
            for node in self.nodes:
                writer.writerow([node, node])
        
        # Edges file
        edges_file = output_file.replace('.csv', '_edges.csv')
        with open(edges_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Source', 'Target', 'Weight', 'Type'])
            for (from_ip, to_ip), data in self.edges.items():
                writer.writerow([from_ip, to_ip, data["count"], 'Directed'])
        
        print(f"Gephi files exported:")
        print(f"  Nodes: {nodes_file}")
        print(f"  Edges: {edges_file}")
    
    def generate_statistics(self) -> Dict:
        """Generate graph statistics"""
        in_degree = defaultdict(int)
        out_degree = defaultdict(int)
        
        for (from_ip, to_ip), data in self.edges.items():
            out_degree[from_ip] += data["count"]
            in_degree[to_ip] += data["count"]
        
        # Find hub nodes (high degree)
        hubs = []
        for node in self.nodes:
            total_degree = in_degree[node] + out_degree[node]
            if total_degree > 10:
                hubs.append({
                    "ip": node,
                    "in_degree": in_degree[node],
                    "out_degree": out_degree[node],
                    "total_degree": total_degree
                })
        
        hubs.sort(key=lambda x: x["total_degree"], reverse=True)
        
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "total_connections": sum(data["count"] for data in self.edges.values()),
            "top_hubs": hubs[:20]
        }


class ISPIdentifier:
    """Identify which ISP infrastructure routers belong to"""
    
    # Known IP ranges for major Taiwan ISPs
    ISP_PATTERNS = {
        "HiNet": [
            r"^168\.95\.",           # HiNet primary range
            r"^203\.66\.",           # HiNet range
            r"^61\.56\.",            # HiNet range
            r"^61\.57\.",            # HiNet range
            r"^220\.128\.",          # HiNet range
        ],
        "SEEDnet": [
            r"^139\.175\.",          # SEEDnet primary
            r"^210\.59\.",           # SEEDnet range
            r"^210\.65\.",           # SEEDnet range
        ],
        "Taiwan Fixed Network": [
            r"^210\.241\.",          # TWM fixed
            r"^203\.133\.",          # TWM range
        ],
        "TWAREN": [
            r"^163\.28\.",           # TWAREN
            r"^140\.110\.",          # TWAREN/TANet
        ]
    }
    
    @classmethod
    def identify_isp(cls, ip: str) -> str:
        """Identify ISP from IP address"""
        for isp, patterns in cls.ISP_PATTERNS.items():
            for pattern in patterns:
                if re.match(pattern, ip):
                    return isp
        return "Unknown"
    
    @classmethod
    def analyze_isp_usage(cls, results: List[Dict]) -> Dict:
        """Analyze ISP infrastructure usage across all paths"""
        isp_counts = defaultdict(lambda: {
            "router_count": 0,
            "unique_routers": set(),
            "targets": set(),
            "categories": set()
        })
        
        for result in results:
            for hop in result["hops"]:
                if hop["ip"] and hop["ip"] != "*":
                    isp = cls.identify_isp(hop["ip"])
                    isp_counts[isp]["router_count"] += 1
                    isp_counts[isp]["unique_routers"].add(hop["ip"])
                    isp_counts[isp]["targets"].add(result["target"])
                    isp_counts[isp]["categories"].add(result.get("category", "unknown"))
        
        # Convert to serializable format
        isp_stats = {}
        for isp, data in isp_counts.items():
            isp_stats[isp] = {
                "total_appearances": data["router_count"],
                "unique_routers": len(data["unique_routers"]),
                "unique_targets": len(data["targets"]),
                "categories": list(data["categories"])
            }
        
        return isp_stats


class ComprehensiveAnalyzer:
    """Main analyzer that runs all analysis modules"""
    
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.results = []
        self.load_results()
    
    def load_results(self):
        """Load all traceroute results"""
        # Try to load from summary file first
        summary_files = list(self.data_dir.glob("summary_*.json"))
        if summary_files:
            latest_summary = max(summary_files, key=lambda p: p.stat().st_mtime)
            with open(latest_summary, 'r') as f:
                data = json.load(f)
                self.results = data.get("results", [])
        else:
            # Load from individual files
            raw_dir = self.data_dir / "raw"
            if raw_dir.exists():
                for json_file in raw_dir.glob("*.json"):
                    with open(json_file, 'r') as f:
                        self.results.append(json.load(f))
        
        print(f"Loaded {len(self.results)} traceroute results")
    
    def run_full_analysis(self):
        """Run comprehensive analysis"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = self.data_dir / f"analysis_{timestamp}"
        report_dir.mkdir(exist_ok=True)
        
        print(f"\n{'='*80}")
        print("COMPREHENSIVE TOPOLOGY ANALYSIS")
        print(f"{'='*80}\n")
        
        # 1. Path Analysis
        print("1. Analyzing AS-level paths...")
        path_analyzer = PathAnalyzer(self.results)
        as_paths = path_analyzer.find_as_paths()
        
        with open(report_dir / "as_paths.json", 'w') as f:
            json.dump(as_paths, f, indent=2)
        print(f"   Found {len(as_paths)} AS-level paths")
        
        # 2. Border identification
        print("2. Identifying AS borders...")
        borders = path_analyzer.identify_as_borders(as_paths)
        
        with open(report_dir / "as_borders.json", 'w') as f:
            json.dump(borders, f, indent=2)
        print(f"   Found {len(borders)} AS border crossings")
        
        # 3. Peering analysis
        print("3. Analyzing peering relationships...")
        peering_data = path_analyzer.find_peering_points(borders)
        
        with open(report_dir / "peering_points.json", 'w') as f:
            json.dump(peering_data, f, indent=2)
        print(f"   Found {peering_data['total_unique_peerings']} unique peering relationships")
        
        # 4. Load balancing detection
        print("4. Detecting load balancing...")
        load_balanced = path_analyzer.detect_load_balancing()
        
        with open(report_dir / "load_balancing.json", 'w') as f:
            json.dump(load_balanced, f, indent=2)
        print(f"   Found {len(load_balanced)} targets with multiple paths")
        
        # 5. Latency analysis
        print("5. Analyzing latency patterns...")
        latency_stats = path_analyzer.analyze_latency_patterns()
        
        with open(report_dir / "latency_stats.json", 'w') as f:
            json.dump(latency_stats, f, indent=2)
        
        # 6. Graph generation
        print("6. Generating topology graphs...")
        graph_gen = TopologyGraphGenerator(self.results)
        graph_gen.build_graph()
        
        graph_gen.export_graphviz(str(report_dir / "topology.dot"))
        graph_gen.export_gephi(str(report_dir / "topology.csv"))
        
        graph_stats = graph_gen.generate_statistics()
        with open(report_dir / "graph_statistics.json", 'w') as f:
            json.dump(graph_stats, f, indent=2)
        print(f"   Graph: {graph_stats['total_nodes']} nodes, {graph_stats['total_edges']} edges")
        
        # 7. ISP identification
        print("7. Analyzing ISP infrastructure usage...")
        isp_stats = ISPIdentifier.analyze_isp_usage(self.results)
        
        with open(report_dir / "isp_analysis.json", 'w') as f:
            json.dump(isp_stats, f, indent=2)
        
        # 8. Generate comprehensive report
        print("8. Generating final report...")
        self._generate_comprehensive_report(
            report_dir,
            as_paths,
            borders,
            peering_data,
            load_balanced,
            latency_stats,
            graph_stats,
            isp_stats
        )
        
        print(f"\n{'='*80}")
        print(f"Analysis complete! Results saved to: {report_dir}")
        print(f"{'='*80}\n")
        
        return report_dir
    
    def _generate_comprehensive_report(self, report_dir, as_paths, borders,
                                      peering_data, load_balanced, latency_stats,
                                      graph_stats, isp_stats):
        """Generate human-readable comprehensive report"""
        report_file = report_dir / "COMPREHENSIVE_REPORT.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*100 + "\n")
            f.write("TAIWAN ISP TOPOLOGY MAPPING - COMPREHENSIVE ANALYSIS REPORT\n")
            f.write("="*100 + "\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*100 + "\n")
            f.write(f"Total Measurements: {len(self.results)}\n")
            f.write(f"AS-Level Paths: {len(as_paths)}\n")
            f.write(f"AS Border Crossings: {len(borders)}\n")
            f.write(f"Unique Peering Relationships: {peering_data['total_unique_peerings']}\n")
            f.write(f"Load-Balanced Targets: {len(load_balanced)}\n")
            f.write(f"Network Nodes: {graph_stats['total_nodes']}\n")
            f.write(f"Network Edges: {graph_stats['total_edges']}\n\n")
            
            # Top Peering Relationships
            f.write("\nTOP PEERING RELATIONSHIPS\n")
            f.write("-"*100 + "\n")
            for i, peering in enumerate(peering_data['peerings'][:15], 1):
                f.write(f"{i}. AS{peering['from_asn']} -> AS{peering['to_asn']}\n")
                f.write(f"   Occurrences: {peering['occurrences']}\n")
                f.write(f"   Unique targets: {peering['unique_targets']}\n")
                f.write(f"   IP pairs: {peering['unique_ip_pairs']}\n\n")
            
            # Top Hub Routers
            f.write("\nTOP HUB ROUTERS (Core Infrastructure)\n")
            f.write("-"*100 + "\n")
            for i, hub in enumerate(graph_stats['top_hubs'][:20], 1):
                isp = ISPIdentifier.identify_isp(hub['ip'])
                f.write(f"{i}. {hub['ip']} ({isp})\n")
                f.write(f"   Total degree: {hub['total_degree']}\n")
                f.write(f"   In-degree: {hub['in_degree']}, Out-degree: {hub['out_degree']}\n\n")
            
            # ISP Infrastructure Usage
            f.write("\nISP INFRASTRUCTURE USAGE\n")
            f.write("-"*100 + "\n")
            for isp, stats in sorted(isp_stats.items(), 
                                    key=lambda x: x[1]['total_appearances'], 
                                    reverse=True):
                f.write(f"\n{isp}:\n")
                f.write(f"  Total router appearances: {stats['total_appearances']}\n")
                f.write(f"  Unique routers: {stats['unique_routers']}\n")
                f.write(f"  Unique targets reached: {stats['unique_targets']}\n")
                f.write(f"  Categories: {', '.join(stats['categories'])}\n")
            
            # Load Balancing Summary
            if load_balanced:
                f.write("\n\nLOAD BALANCING DETECTED\n")
                f.write("-"*100 + "\n")
                for lb in load_balanced[:10]:
                    f.write(f"\nTarget: {lb['target']}\n")
                    f.write(f"  Unique paths: {lb['unique_paths']}\n")
                    f.write(f"  Total measurements: {lb['total_measurements']}\n")
            
            # Latency Summary
            f.write("\n\nLATENCY ANALYSIS BY HOP\n")
            f.write("-"*100 + "\n")
            f.write(f"{'Hop':<6} {'Min (ms)':<12} {'Avg (ms)':<12} {'Max (ms)':<12} {'Samples':<10}\n")
            f.write("-"*100 + "\n")
            for hop_num, stats in sorted(latency_stats.items())[:15]:
                f.write(f"{hop_num:<6} {stats['min']:<12.2f} {stats['avg']:<12.2f} "
                       f"{stats['max']:<12.2f} {stats['count']:<10}\n")


# Additional utility functions

def compare_vantage_points(data_dir1: str, data_dir2: str, output_file: str):
    """Compare traceroutes from two different vantage points"""
    print("Comparing vantage points...")
    
    # Load data from both vantage points
    analyzer1 = ComprehensiveAnalyzer(data_dir1)
    analyzer2 = ComprehensiveAnalyzer(data_dir2)
    
    # Build path signatures for comparison
    paths1 = {}
    paths2 = {}
    
    for result in analyzer1.results:
        target = result["target"]
        path = tuple(hop["ip"] for hop in result["hops"] if hop["ip"])
        paths1[target] = path
    
    for result in analyzer2.results:
        target = result["target"]
        path = tuple(hop["ip"] for hop in result["hops"] if hop["ip"])
        paths2[target] = path
    
    # Find differences
    common_targets = set(paths1.keys()) & set(paths2.keys())
    different_paths = []
    
    for target in common_targets:
        if paths1[target] != paths2[target]:
            different_paths.append({
                "target": target,
                "vp1_path": list(paths1[target]),
                "vp2_path": list(paths2[target])
            })
    
    # Save comparison
    with open(output_file, 'w') as f:
        json.dump({
            "vantage_point_1": data_dir1,
            "vantage_point_2": data_dir2,
            "common_targets": len(common_targets),
            "different_paths": len(different_paths),
            "similarity": 1 - (len(different_paths) / len(common_targets)) if common_targets else 0,
            "details": different_paths
        }, f, indent=2)
    
    print(f"Comparison saved to {output_file}")
    print(f"  Common targets: {len(common_targets)}")
    print(f"  Different paths: {len(different_paths)}")
    print(f"  Similarity: {(1 - len(different_paths)/len(common_targets))*100:.1f}%")


if __name__ == "__main__":
    import sys
    from datetime import datetime
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python topology_analysis.py <data_directory>")
        print("  python topology_analysis.py compare <dir1> <dir2> <output_file>")
        sys.exit(1)
    
    if sys.argv[1] == "compare" and len(sys.argv) >= 5:
        compare_vantage_points(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        analyzer = ComprehensiveAnalyzer(sys.argv[1])
        analyzer.run_full_analysis()