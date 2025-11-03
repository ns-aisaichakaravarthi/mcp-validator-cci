#!/usr/bin/env python3
"""
MCP Server Security Validator

Automated security testing tool for MCP (Model Context Protocol) servers.

Usage:
    python3 mcp_validator.py --list
    python3 mcp_validator.py --server canva_mcp_server --verbose
    python3 mcp_validator.py --all --verbose
    python3 mcp_validator.py --config custom_config.json --all
"""

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Import the validator
from mcp_validator_lib import MCPServerSecurityValidator


# ==============================================================================
# CONFIGURATION LOADER
# ==============================================================================

class ConfigLoader:
    """Loads and parses MCP server configuration files."""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            # Default to local config
            self.config_path = Path("mcp_clean.json")
        else:
            self.config_path = Path(config_path)
    
    def load(self) -> Dict[str, Any]:
        """Load configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                print(f"✅ Loaded configuration from: {self.config_path}")
                return config
        except FileNotFoundError:
                print(f"❌ Config not found: {self.config_path}")
            print(f"\n💡 Please provide a valid configuration file.")
                sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in config: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            sys.exit(1)
    
    def get_servers(self, config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract MCP servers from configuration."""
        mcp_servers = config.get('mcpServers', {})
        
        # Convert to unified format
        servers = {}
        for server_name, server_config in mcp_servers.items():
            # Handle both 'transport' and 'type' fields
            transport = server_config.get('transport') or server_config.get('type', 'http')
            
            # Handle both 'httpUrl' and 'url' fields
            http_url = server_config.get('httpUrl') or server_config.get('url', '')
            
            # Get description
            description = server_config.get('description', f'MCP Server ({transport})')
            
            servers[server_name] = {
                'type': transport,
                'url': http_url,
                'description': description,
                'headers': server_config.get('headers', {}),
                'original_config': server_config  # Keep original config
            }
        
        return servers


# ==============================================================================
# MAIN SCRIPT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MCP Server Security Validator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List servers
  python3 mcp_validator.py --list

  # Test single server
  python3 mcp_validator.py --server canva_mcp_server --verbose

  # Test all servers
  python3 mcp_validator.py --all --verbose

  # Use custom config
  python3 mcp_validator.py --config my_servers.json --all
        """
    )
    
    parser.add_argument('--config', default='mcp_clean.json',
                        help='Path to config file (default: mcp_clean.json)')
    parser.add_argument('--server', help='Server name from config')
    parser.add_argument('--all', action='store_true', help='Test all servers')
    parser.add_argument('--list', action='store_true', help='List servers')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output-dir', default='reports', help='Output directory')
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("🛡️  MCP SERVER SECURITY VALIDATOR")
    print("=" * 70)
    print()
    
    # Load configuration
    loader = ConfigLoader(args.config)
    config = loader.load()
    servers = loader.get_servers(config)
    
    print(f"📋 Found {len(servers)} server(s) in config\n")
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # List servers
    if args.list:
        print("Available servers:\n")
        for server_name, server_info in servers.items():
            print(f"  • {server_name}")
            print(f"    URL: {server_info['url']}")
            print(f"    Transport: {server_info['type']}")
            print()
        return
    
    # Test all servers
    if args.all:
        print(f"🧪 Testing all {len(servers)} servers...\n")
        
        all_results = []
        
        for idx, (server_name, server_config) in enumerate(servers.items(), 1):
            print("=" * 70)
            print(f"[{idx}/{len(servers)}] Testing: {server_name}")
            print("=" * 70)
            print()
            
            validator = MCPServerSecurityValidator(
                server_name=server_name,
                server_config=server_config,
                verbose=args.verbose
            )
            
            results = validator.run_all_tests()
            all_results.append(results)
            
            # Save individual report
            output_file = os.path.join(args.output_dir, f"{server_name}_security_report.json")
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"📊 Report saved: {output_file}\n")
        
        # Save combined report
        combined_file = os.path.join(args.output_dir, "all_servers_security_report.json")
        with open(combined_file, 'w') as f:
            json.dump({
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'config_path': str(loader.config_path),
                'total_servers': len(servers),
                'results': all_results
            }, f, indent=2)
        
        print(f"📊 Combined report: {combined_file}\n")
        
        # Print summary
        print("=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print()
        
        for result in all_results:
            server_name = result['server_name']
            rating = result.get('security_rating', 'N/A')
            score = result.get('overall_security_score', 0)
            
            # Rating emoji
            rating_emoji = {
                'EXCELLENT': '🟢',
                'GOOD': '🟢',
                'FAIR': '🟡',
                'POOR': '🟠',
                'CRITICAL': '🔴'
            }.get(rating, '⚪')
            
            print(f"{rating_emoji} {server_name}: {rating} ({score}/100)")
        
        print()
        return
    
    # Test single server
    if args.server:
        if args.server not in servers:
            print(f"❌ Error: Server '{args.server}' not found in config")
            print(f"\nAvailable servers: {', '.join(servers.keys())}")
            sys.exit(1)
        
        server_config = servers[args.server]
        
        validator = MCPServerSecurityValidator(
            server_name=args.server,
            server_config=server_config,
            verbose=args.verbose
        )
        
        results = validator.run_all_tests()
        
        # Save report
        output_file = os.path.join(args.output_dir, f"{args.server}_security_report.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n📄 Report saved: {output_file}\n")
        return
    
    # No action specified
    parser.print_help()


if __name__ == "__main__":
    main()
