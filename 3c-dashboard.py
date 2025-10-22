#!/usr/bin/env python3
"""
Real-time Monitoring Dashboard for Taiwan ISP Topology Mapping
Tracks collection progress and provides live statistics
"""

import json
import time
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import sys

class CollectionMonitor:
    def __init__(self, data_dir: str = "traceroute_data"):
        self.data_dir = Path(data_dir)
        self.raw_dir = self.data_dir / "raw"
        self.start_time = None
        self.last_file_count = 0
        
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def get_collection_stats(self):
        """Gather current collection statistics"""
        if not self.raw_dir.exists():
            return None
        
        json_files = list(self.raw_dir.glob("*.json"))
        
        if not json_files:
            return None
        
        # Parse all result files
        results = []
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    results.append(json.load(f))
            except:
                continue
        
        if not results:
            return None
        
        # Calculate statistics
        timestamps = [datetime.fromisoformat(r['timestamp']) for r in results]
        
        stats = {
            'total_traceroutes': len(results),
            'successful': sum(1 for r in results if r.get('success')),
            'failed': sum(1 for r in results if not r.get('success')),
            'start_time': min(timestamps),
            'latest_time': max(timestamps),
            'duration': max(timestamps) - min(timestamps),
            'categories': defaultdict(int),
            'protocols': defaultdict(int),
            'targets': set(),
            'vantage_points': set(),
            'unique_ips': set(),
            'total_hops': 0,
            'avg_hops': 0
        }
        
        # Detailed statistics
        for result in results:
            stats['categories'][result.get('category', 'unknown')] += 1
            stats['protocols'][result.get('protocol', 'unknown')] += 1
            stats['targets'].add(result['target'])
            stats['vantage_points'].add(result.get('vantage_point', 'unknown'))
            stats['total_hops'] += result.get('num_hops', 0)
            
            for hop in result.get('hops', []):
                if hop.get('ip'):
                    stats['unique_ips'].add(hop['ip'])
        
        if stats['total_traceroutes'] > 0:
            stats['avg_hops'] = stats['total_hops'] / stats['total_traceroutes']
        
        # Calculate rate
        if stats['duration'].total_seconds() > 0:
            stats['rate_per_minute'] = stats['total_traceroutes'] / (stats['duration'].total_seconds() / 60)
        else:
            stats['rate_per_minute'] = 0
        
        return stats
    
    def estimate_completion(self, stats, total_targets=165, protocols_per_target=3):
        """Estimate completion time"""
        if not stats or stats['rate_per_minute'] == 0:
            return None
        
        expected_total = total_targets * protocols_per_target
        remaining = expected_total - stats['total_traceroutes']
        
        if remaining <= 0:
            return {
                'completed': True,
                'remaining_count': 0,
                'eta': None
            }
        
        minutes_remaining = remaining / stats['rate_per_minute']
        eta = datetime.now() + timedelta(minutes=minutes_remaining)
        
        return {
            'completed': False,
            'remaining_count': remaining,
            'minutes_remaining': minutes_remaining,
            'eta': eta,
            'progress_percentage': (stats['total_traceroutes'] / expected_total) * 100
        }
    
    def format_duration(self, td):
        """Format timedelta for display"""
        total_seconds = int(td.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def display_dashboard(self, stats, completion_info):
        """Display monitoring dashboard"""
        self.clear_screen()
        
        print("=" * 100)
        print(" " * 30 + "TAIWAN ISP TOPOLOGY MAPPING - LIVE MONITOR")
        print("=" * 100)
        print()
        
        if not stats:
            print("No data collected yet. Waiting for collection to start...")
            print()
            print("Data directory:", self.data_dir)
            print("Expected location:", self.raw_dir)
            return
        
        # Header
        print(f"📊 COLLECTION STATUS")
        print("-" * 100)
        print(f"Started:        {stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Latest Update:  {stats['latest_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration:       {self.format_duration(stats['duration'])}")
        print()
        
        # Progress
        if completion_info:
            progress = completion_info.get('progress_percentage', 0)
            bar_length = 50
            filled = int(bar_length * progress / 100)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            print(f"📈 PROGRESS")
            print("-" * 100)
            print(f"[{bar}] {progress:.1f}%")
            print()
            
            if not completion_info['completed']:
                print(f"Remaining:      {completion_info['remaining_count']} traceroutes")
                print(f"Estimated Time: {self.format_duration(timedelta(minutes=completion_info['minutes_remaining']))}")
                print(f"ETA:            {completion_info['eta'].strftime('%Y-%m-%d %H:%M:%S')}")
            else:
                print("✅ Collection appears complete!")
            print()
        
        # Statistics
        print(f"📋 STATISTICS")
        print("-" * 100)
        print(f"Total Traceroutes:    {stats['total_traceroutes']:>6}")
        print(f"  ✓ Successful:       {stats['successful']:>6}  ({stats['successful']/stats['total_traceroutes']*100:.1f}%)")
        print(f"  ✗ Failed:           {stats['failed']:>6}  ({stats['failed']/stats['total_traceroutes']*100:.1f}%)")
        print(f"Unique Targets:       {len(stats['targets']):>6}")
        print(f"Unique IPs Seen:      {len(stats['unique_ips']):>6}")
        print(f"Average Hops:         {stats['avg_hops']:>6.1f}")
        print(f"Collection Rate:      {stats['rate_per_minute']:>6.2f} traceroutes/min")
        print()
        
        # Vantage Points
        print(f"🌐 VANTAGE POINTS")
        print("-" * 100)
        for vp in sorted(stats['vantage_points']):
            print(f"  • {vp}")
        print()
        
        # Categories
        print(f"📁 CATEGORIES")
        print("-" * 100)
        sorted_categories = sorted(stats['categories'].items(), key=lambda x: x[1], reverse=True)
        for category, count in sorted_categories[:10]:
            bar_len = int(40 * count / stats['total_traceroutes'])
            bar = '▓' * bar_len + '░' * (40 - bar_len)
            print(f"  {category:<30} [{bar}] {count:>4}")
        print()
        
        # Protocols
        print(f"🔧 PROTOCOLS")
        print("-" * 100)
        for protocol, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = count / stats['total_traceroutes'] * 100
            print(f"  {protocol:<15} {count:>6} ({percentage:>5.1f}%)")
        print()
        
        # Recent Activity
        print(f"⏱️  RECENT ACTIVITY")
        print("-" * 100)
        new_files = stats['total_traceroutes'] - self.last_file_count
        if new_files > 0:
            print(f"  New traceroutes since last update: {new_files}")
        else:
            print(f"  No new traceroutes in last update cycle")
        self.last_file_count = stats['total_traceroutes']
        print()
        
        # Footer
        print("=" * 100)
        print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Press Ctrl+C to exit")
        print("=" * 100)
    
    def run(self, update_interval=5):
        """Run monitoring loop"""
        print("Starting Taiwan ISP Topology Mapping Monitor...")
        print(f"Monitoring directory: {self.data_dir}")
        print(f"Update interval: {update_interval} seconds")
        print()
        
        try:
            while True:
                stats = self.get_collection_stats()
                completion_info = self.estimate_completion(stats) if stats else None
                self.display_dashboard(stats, completion_info)
                time.sleep(update_interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user.")
            if stats:
                print(f"\nFinal Statistics:")
                print(f"  Total traceroutes: {stats['total_traceroutes']}")
                print(f"  Unique targets: {len(stats['targets'])}")
                print(f"  Duration: {self.format_duration(stats['duration'])}")
            sys.exit(0)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Monitor Taiwan ISP topology mapping collection in real-time"
    )
    parser.add_argument(
        '--data-dir',
        default='traceroute_data',
        help='Data directory to monitor (default: traceroute_data)'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='Update interval in seconds (default: 5)'
    )
    parser.add_argument(
        '--targets',
        type=int,
        default=165,
        help='Expected total targets (default: 165)'
    )
    parser.add_argument(
        '--protocols',
        type=int,
        default=3,
        help='Protocols per target (default: 3)'
    )
    
    args = parser.parse_args()
    
    monitor = CollectionMonitor(args.data_dir)
    monitor.run(args.interval)


if __name__ == "__main__":
    main()