#!/usr/bin/env python3
"""
Router JSON to Text Formatter
Converts router JSON files to readable text reports
"""

import json
import argparse
from pathlib import Path
from datetime import datetime


class RouterFormatter:
    def __init__(self, json_file: str):
        self.json_file = Path(json_file)
        self.data = None
        
    def load_data(self):
        """Load router data from JSON file"""
        with open(self.json_file, 'r') as f:
            self.data = json.load(f)
        print(f"Loaded {self.data.get('total_routers', 0)} routers from {self.json_file}")
    
    def generate_summary_report(self, output_file: str = None, top_n: int = None):
        """Generate a summary report with basic info"""
        if not output_file:
            output_file = self.json_file.parent / f"routers_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        routers = self.data.get('routers', [])
        total_routers = len(routers)
        
        # Only limit if top_n is specified and not -1 (which means all)
        if top_n and top_n != -1:
            routers = routers[:top_n]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 120 + "\n")
            f.write("ROUTER DISCOVERY SUMMARY REPORT\n")
            f.write("=" * 120 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.data.get('vantage_point', 'unknown')}\n")
            f.write(f"Collection Time: {self.data.get('timestamp', 'unknown')}\n")
            f.write(f"Total Routers: {total_routers}\n")
            if top_n and top_n != -1:
                f.write(f"Showing: Top {top_n} routers by appearances\n")
            else:
                f.write(f"Showing: All routers\n")
            f.write("=" * 120 + "\n\n")
            
            # Table format
            f.write(f"{'Rank':<6} {'Hostname':<50} {'IP Address':<18} {'Appearances':<12} {'Targets':<10}\n")
            f.write("-" * 120 + "\n")
            
            for i, router in enumerate(routers, 1):
                hostname = router.get('hostname', 'No hostname')[:48]
                ip = router.get('ip', 'unknown')
                appearances = router.get('appearances', 0)
                num_targets = len(router.get('targets', []))
                
                f.write(f"{i:<6} {hostname:<50} {ip:<18} {appearances:<12} {num_targets:<10}\n")
            
            f.write("\n" + "=" * 120 + "\n")
        
        print(f"Summary report generated: {output_file}")
        return output_file
    
    def generate_detailed_report(self, output_file: str = None, top_n: int = 50):
        """Generate a detailed report with full information"""
        if not output_file:
            output_file = self.json_file.parent / f"routers_detailed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        routers = self.data.get('routers', [])
        total_routers = len(routers)
        
        # Only limit if top_n is specified and not -1
        if top_n and top_n != -1:
            routers = routers[:top_n]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 120 + "\n")
            f.write("DETAILED ROUTER ANALYSIS REPORT\n")
            f.write("=" * 120 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.data.get('vantage_point', 'unknown')}\n")
            f.write(f"Collection Time: {self.data.get('timestamp', 'unknown')}\n")
            f.write(f"Total Routers: {total_routers}\n")
            if top_n and top_n != -1:
                f.write(f"Showing: Top {top_n} routers by appearances\n")
            else:
                f.write(f"Showing: All routers\n")
            f.write("=" * 120 + "\n\n")
            
            # Detailed entries
            for i, router in enumerate(routers, 1):
                hostname = router.get('hostname', 'No hostname')
                ip = router.get('ip', 'unknown')
                appearances = router.get('appearances', 0)
                targets = router.get('targets', [])
                categories = router.get('categories', [])
                
                f.write(f"{i}. {hostname}\n")
                f.write(f"   {'─' * 110}\n")
                f.write(f"   IP Address:        {ip}\n")
                f.write(f"   Appearances:       {appearances}\n")
                f.write(f"   Unique Targets:    {len(targets)}\n")
                f.write(f"   Categories:        {', '.join(categories)}\n")
                f.write(f"\n")
                
                # Show sample targets (first 10)
                f.write(f"   Sample Targets ({min(10, len(targets))} of {len(targets)}):\n")
                for j, target in enumerate(targets[:10], 1):
                    f.write(f"      {j:2d}. {target}\n")
                
                if len(targets) > 10:
                    f.write(f"      ... and {len(targets) - 10} more targets\n")
                
                f.write("\n")
            
            f.write("=" * 120 + "\n")
        
        print(f"Detailed report generated: {output_file}")
        return output_file
    
    def generate_by_category_report(self, output_file: str = None):
        """Generate a report organized by category"""
        if not output_file:
            output_file = self.json_file.parent / f"routers_by_category_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Organize routers by category
        category_routers = {}
        
        for router in self.data.get('routers', []):
            for category in router.get('categories', []):
                if category not in category_routers:
                    category_routers[category] = []
                category_routers[category].append(router)
        
        # Sort categories by number of routers
        sorted_categories = sorted(category_routers.items(), 
                                  key=lambda x: len(x[1]), 
                                  reverse=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 120 + "\n")
            f.write("ROUTERS BY CATEGORY REPORT\n")
            f.write("=" * 120 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.data.get('vantage_point', 'unknown')}\n")
            f.write(f"Total Categories: {len(category_routers)}\n")
            f.write("=" * 120 + "\n\n")
            
            for category, routers in sorted_categories:
                f.write(f"\n{'═' * 120}\n")
                f.write(f"CATEGORY: {category.upper()}\n")
                f.write(f"{'═' * 120}\n")
                f.write(f"Routers in this category: {len(routers)}\n\n")
                
                # Sort routers by appearances within category
                routers.sort(key=lambda x: x.get('appearances', 0), reverse=True)
                
                # Show top 20 routers per category
                for i, router in enumerate(routers[:20], 1):
                    hostname = router.get('hostname', 'No hostname')[:70]
                    ip = router.get('ip', 'unknown')
                    appearances = router.get('appearances', 0)
                    num_targets = len(router.get('targets', []))
                    
                    f.write(f"  {i:2d}. {hostname}\n")
                    f.write(f"      IP: {ip:<18}  Appearances: {appearances:<6}  Targets: {num_targets}\n")
                
                if len(routers) > 20:
                    f.write(f"\n  ... and {len(routers) - 20} more routers in this category\n")
                
                f.write("\n")
            
            f.write("=" * 120 + "\n")
        
        print(f"By-category report generated: {output_file}")
        return output_file
    
    def generate_network_ownership_report(self, output_file: str = None):
        """Generate a report grouped by network ownership (inferred from hostname)"""
        if not output_file:
            output_file = self.json_file.parent / f"routers_by_network_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Group routers by network (extracted from hostname)
        network_groups = {
            'HiNet': [],
            'TWaren': [],
            'TANet': [],
            'SEEDNet': [],
            'SO-NET': [],
            'CHT': [],
            'FETNet': [],
            'Taiwan Mobile': [],
            'APTG': [],
            'Government (.gov.tw)': [],
            'Education (.edu.tw)': [],
            'Other': []
        }
        
        for router in self.data.get('routers', []):
            hostname = router.get('hostname', '').lower()
            categorized = False
            
            if 'hinet' in hostname:
                network_groups['HiNet'].append(router)
                categorized = True
            elif 'twaren' in hostname:
                network_groups['TWaren'].append(router)
                categorized = True
            elif 'tanet' in hostname or 'edu.tw' in hostname:
                network_groups['TANet'].append(router)
                categorized = True
            elif 'seednet' in hostname:
                network_groups['SEEDNet'].append(router)
                categorized = True
            elif 'so-net' in hostname:
                network_groups['SO-NET'].append(router)
                categorized = True
            elif 'cht.com' in hostname:
                network_groups['CHT'].append(router)
                categorized = True
            elif 'fetnet' in hostname:
                network_groups['FETNet'].append(router)
                categorized = True
            elif 'taiwanmobile' in hostname:
                network_groups['Taiwan Mobile'].append(router)
                categorized = True
            elif 'aptg' in hostname:
                network_groups['APTG'].append(router)
                categorized = True
            elif '.gov.tw' in hostname:
                network_groups['Government (.gov.tw)'].append(router)
                categorized = True
            elif '.edu.tw' in hostname and not categorized:
                network_groups['Education (.edu.tw)'].append(router)
                categorized = True
            
            if not categorized:
                network_groups['Other'].append(router)
        
        # Remove empty groups
        network_groups = {k: v for k, v in network_groups.items() if v}
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 120 + "\n")
            f.write("ROUTERS BY NETWORK OWNERSHIP REPORT\n")
            f.write("=" * 120 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vantage Point: {self.data.get('vantage_point', 'unknown')}\n")
            f.write("=" * 120 + "\n\n")
            
            # Summary table
            f.write("NETWORK SUMMARY\n")
            f.write("-" * 120 + "\n")
            f.write(f"{'Network':<30} {'Router Count':<15} {'Total Appearances':<20}\n")
            f.write("-" * 120 + "\n")
            
            sorted_networks = sorted(network_groups.items(), 
                                   key=lambda x: len(x[1]), 
                                   reverse=True)
            
            for network, routers in sorted_networks:
                total_appearances = sum(r.get('appearances', 0) for r in routers)
                f.write(f"{network:<30} {len(routers):<15} {total_appearances:<20}\n")
            
            f.write("\n\n")
            
            # Detailed sections
            for network, routers in sorted_networks:
                f.write(f"\n{'═' * 120}\n")
                f.write(f"NETWORK: {network}\n")
                f.write(f"{'═' * 120}\n")
                f.write(f"Total Routers: {len(routers)}\n")
                f.write(f"Total Appearances: {sum(r.get('appearances', 0) for r in routers)}\n\n")
                
                # Sort by appearances
                routers.sort(key=lambda x: x.get('appearances', 0), reverse=True)
                
                f.write(f"{'Rank':<6} {'Hostname':<50} {'IP Address':<18} {'Appearances':<12}\n")
                f.write("-" * 120 + "\n")
                
                for i, router in enumerate(routers[:30], 1):
                    hostname = router.get('hostname', 'No hostname')[:48]
                    ip = router.get('ip', 'unknown')
                    appearances = router.get('appearances', 0)
                    
                    f.write(f"{i:<6} {hostname:<50} {ip:<18} {appearances:<12}\n")
                
                if len(routers) > 30:
                    f.write(f"\n... and {len(routers) - 30} more routers\n")
                
                f.write("\n")
            
            f.write("=" * 120 + "\n")
        
        print(f"Network ownership report generated: {output_file}")
        return output_file
    
    def generate_simple_list(self, output_file: str = None):
        """Generate a simple list of routers (hostname and IP only)"""
        if not output_file:
            output_file = self.json_file.parent / f"routers_simple_list_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        routers = self.data.get('routers', [])
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("Router List\n")
            f.write("=" * 80 + "\n")
            f.write(f"Total: {len(routers)} routers\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, router in enumerate(routers, 1):
                hostname = router.get('hostname', 'No hostname')
                ip = router.get('ip', 'unknown')
                f.write(f"{i:4d}. {ip:<18} {hostname}\n")
        
        print(f"Simple list generated: {output_file}")
        return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Router JSON to Text Formatter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate summary report (top 100 routers)
  python3 router_formatter.py interesting_routers_20251022_102303.json --summary
  
  # Generate detailed report with full information
  python3 router_formatter.py interesting_routers_20251022_102303.json --detailed
  
  # Generate report organized by category
  python3 router_formatter.py interesting_routers_20251022_102303.json --by-category
  
  # Generate network ownership analysis
  python3 router_formatter.py interesting_routers_20251022_102303.json --by-network
  
  # Generate all reports
  python3 router_formatter.py interesting_routers_20251022_102303.json --all
  
  # Simple list (just hostname and IP)
  python3 router_formatter.py interesting_routers_20251022_102303.json --simple
  
  # Custom output location and limit
  python3 router_formatter.py interesting_routers_20251022_102303.json --summary --output my_report.txt --top 50
        """
    )
    
    parser.add_argument("json_file", help="Path to router JSON file")
    parser.add_argument("--summary", action="store_true",
                       help="Generate summary report")
    parser.add_argument("--detailed", action="store_true",
                       help="Generate detailed report with full information")
    parser.add_argument("--by-category", action="store_true",
                       help="Generate report organized by category")
    parser.add_argument("--by-network", action="store_true",
                       help="Generate network ownership report")
    parser.add_argument("--simple", action="store_true",
                       help="Generate simple list (hostname and IP only)")
    parser.add_argument("--all", action="store_true",
                       help="Generate all report types")
    parser.add_argument("--output", help="Custom output file path")
    parser.add_argument("--top", type=int, default=100,
                       help="Number of top routers to show (default: 100, use -1 for all)")
    parser.add_argument("--all-routers", action="store_true",
                       help="Show all routers (equivalent to --top -1)")
    
    args = parser.parse_args()
    
    # Load data
    formatter = RouterFormatter(args.json_file)
    formatter.load_data()
    
    # Generate requested reports
    if args.all:
        print("\nGenerating all reports...")
        formatter.generate_summary_report(top_n=args.top)
        formatter.generate_detailed_report(top_n=args.top)
        formatter.generate_by_category_report()
        formatter.generate_network_ownership_report()
        formatter.generate_simple_list()
    else:
        if args.summary:
            formatter.generate_summary_report(args.output, top_n=args.top)
        if args.detailed:
            formatter.generate_detailed_report(args.output, top_n=args.top)
        if args.by_category:
            formatter.generate_by_category_report(args.output)
        if args.by_network:
            formatter.generate_network_ownership_report(args.output)
        if args.simple:
            formatter.generate_simple_list(args.output)
        
        if not any([args.summary, args.detailed, args.by_category, 
                   args.by_network, args.simple]):
            print("No report type specified. Use --summary, --detailed, --by-category, --by-network, --simple, or --all")
            print("Run with --help for more information")
    
    print("\nDone!")


if __name__ == "__main__":
    main()