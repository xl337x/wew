#!/usr/bin/env python3
"""
KerbCracker - Advanced Kerberos Hash Cracking Tool
Automatically detects hash types and cracks them efficiently
For authorized penetration testing only
"""

import subprocess
import sys
import os
import re
from pathlib import Path
from typing import List, Dict, Tuple
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class KerbCracker:
    def __init__(self):
        self.hash_types = {
            'krb5tgs$23': {'mode': 13100, 'name': 'Kerberoast (RC4-HMAC)', 'pattern': r'\$krb5tgs\$23\$[^\s"]+'},
            'krb5tgs$18': {'mode': 19600, 'name': 'Kerberoast (AES256-CTS-HMAC-SHA1-96)', 'pattern': r'\$krb5tgs\$18\$[^\s"]+'},
            'krb5tgs$17': {'mode': 19700, 'name': 'Kerberoast (AES128-CTS-HMAC-SHA1-96)', 'pattern': r'\$krb5tgs\$17\$[^\s"]+'},
            'krb5asrep$23': {'mode': 18200, 'name': 'AS-REP Roasting', 'pattern': r'\$krb5asrep\$23\$[^\s"]+'},
        }
        self.results = []
        
    def banner(self):
        banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  {Colors.BOLD}██╗  ██╗███████╗██████╗ ██████╗  ██████╗██████╗  █████╗  {Colors.END}{Colors.CYAN}  ║
║  {Colors.BOLD}██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗ {Colors.END}{Colors.CYAN}  ║
║  {Colors.BOLD}█████╔╝ █████╗  ██████╔╝██████╔╝██║     ██████╔╝███████║ {Colors.END}{Colors.CYAN}  ║
║  {Colors.BOLD}██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗██║     ██╔══██╗██╔══██║ {Colors.END}{Colors.CYAN}  ║
║  {Colors.BOLD}██║  ██╗███████╗██║  ██║██████╔╝╚██████╗██║  ██║██║  ██║ {Colors.END}{Colors.CYAN}  ║
║  {Colors.BOLD}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ {Colors.END}{Colors.CYAN}  ║
║                                                               ║
║         {Colors.YELLOW}Advanced Kerberos Hash Cracking Suite v1.0{Colors.CYAN}         ║
║              {Colors.GREEN}For Authorized Penetration Testing{Colors.CYAN}             ║
╚═══════════════════════════════════════════════════════════════╝{Colors.END}
"""
        print(banner)

    def extract_hashes(self, input_file: str) -> Dict[str, List[str]]:
        """Extract and categorize hashes from input file"""
        print(f"\n{Colors.BLUE}[*]{Colors.END} Analyzing input file: {input_file}")
        
        categorized = {key: [] for key in self.hash_types.keys()}
        
        try:
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for hash_type, info in self.hash_types.items():
                pattern = info['pattern']
                matches = re.findall(pattern, content)
                categorized[hash_type] = list(set(matches))  # Remove duplicates
                
                if matches:
                    print(f"{Colors.GREEN}[+]{Colors.END} Found {len(categorized[hash_type])} {Colors.CYAN}{info['name']}{Colors.END} hashes")
        
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.END} Error reading file: {e}")
            sys.exit(1)
        
        return categorized

    def crack_hash_type(self, hash_type: str, hashes: List[str], wordlist: str, 
                       rules: str = None, show_only: bool = False) -> List[Dict]:
        """Crack hashes of a specific type"""
        if not hashes:
            return []
        
        info = self.hash_types[hash_type]
        mode = info['mode']
        name = info['name']
        
        # Create temporary hash file
        temp_file = f"/tmp/kerb_temp_{mode}.txt"
        with open(temp_file, 'w') as f:
            f.write('\n'.join(hashes))
        
        print(f"\n{Colors.YELLOW}[*]{Colors.END} Processing {Colors.CYAN}{name}{Colors.END} (mode {mode})")
        
        results = []
        
        # Check for already cracked hashes
        if show_only:
            cmd = ['hashcat', '-m', str(mode), temp_file, '--show']
        else:
            cmd = ['hashcat', '-m', str(mode), temp_file, wordlist, '--force', '--quiet']
            
            if rules:
                cmd.extend(['-r', rules])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if show_only:
                # Parse already cracked hashes
                for line in result.stdout.strip().split('\n'):
                    if line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            results.append({
                                'hash': parts[0],
                                'password': parts[-1],
                                'type': name
                            })
            else:
                # After cracking, get results
                show_cmd = ['hashcat', '-m', str(mode), temp_file, '--show']
                show_result = subprocess.run(show_cmd, capture_output=True, text=True)
                
                for line in show_result.stdout.strip().split('\n'):
                    if line and ':' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            results.append({
                                'hash': parts[0],
                                'password': parts[-1],
                                'type': name
                            })
            
            if results:
                print(f"{Colors.GREEN}[+]{Colors.END} Cracked {len(results)} hashes!")
            else:
                print(f"{Colors.RED}[-]{Colors.END} No hashes cracked for this type")
                
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[!]{Colors.END} Timeout reached for {name}")
        except Exception as e:
            print(f"{Colors.RED}[!]{Colors.END} Error cracking {name}: {e}")
        finally:
            # Cleanup temp file
            if os.path.exists(temp_file):
                os.remove(temp_file)
        
        return results

    def crack_all(self, input_file: str, wordlist: str, rules: str = None, 
                  output: str = None, show_only: bool = False):
        """Main cracking function"""
        self.banner()
        
        # Verify wordlist exists
        if not show_only and not os.path.exists(wordlist):
            print(f"{Colors.RED}[!]{Colors.END} Wordlist not found: {wordlist}")
            sys.exit(1)
        
        # Extract hashes
        categorized = self.extract_hashes(input_file)
        
        total_hashes = sum(len(v) for v in categorized.values())
        if total_hashes == 0:
            print(f"\n{Colors.RED}[!]{Colors.END} No Kerberos hashes found in input file")
            sys.exit(1)
        
        print(f"\n{Colors.BLUE}[*]{Colors.END} Total hashes found: {Colors.BOLD}{total_hashes}{Colors.END}")
        
        if not show_only:
            print(f"{Colors.BLUE}[*]{Colors.END} Wordlist: {wordlist}")
            if rules:
                print(f"{Colors.BLUE}[*]{Colors.END} Rules: {rules}")
            print(f"\n{Colors.YELLOW}[*]{Colors.END} Starting cracking process...")
        
        # Crack each hash type
        all_results = []
        for hash_type, hashes in categorized.items():
            if hashes:
                results = self.crack_hash_type(hash_type, hashes, wordlist, rules, show_only)
                all_results.extend(results)
        
        # Display results
        self.display_results(all_results, output)
        
        return all_results

    def display_results(self, results: List[Dict], output_file: str = None):
        """Display and save cracking results"""
        if not results:
            print(f"\n{Colors.RED}[!]{Colors.END} No passwords cracked")
            return
        
        print(f"\n{Colors.GREEN}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.GREEN}CRACKED PASSWORDS ({len(results)}){Colors.END}")
        print(f"{Colors.GREEN}{'='*70}{Colors.END}\n")
        
        for result in results:
            # Extract username from hash if possible
            username = "Unknown"
            hash_str = result['hash']
            
            # Try to extract username from hash
            match = re.search(r'\*([^$*]+)\$', hash_str)
            if match:
                username = match.group(1)
            
            print(f"{Colors.CYAN}User:{Colors.END} {username}")
            print(f"{Colors.YELLOW}Pass:{Colors.END} {Colors.BOLD}{Colors.GREEN}{result['password']}{Colors.END}")
            print(f"{Colors.BLUE}Type:{Colors.END} {result['type']}")
            print(f"{Colors.RED}Hash:{Colors.END} {hash_str[:80]}...")
            print(f"{Colors.GREEN}{'-'*70}{Colors.END}\n")
        
        # Save to file
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    for result in results:
                        match = re.search(r'\*([^$*]+)\$', result['hash'])
                        username = match.group(1) if match else "Unknown"
                        f.write(f"{username}:{result['password']}\n")
                print(f"{Colors.GREEN}[+]{Colors.END} Results saved to: {output_file}")
            except Exception as e:
                print(f"{Colors.RED}[!]{Colors.END} Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='KerbCracker - Advanced Kerberos Hash Cracking Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Crack hashes with rockyou wordlist
  ./kerbcracker.py -i hashes.txt -w /usr/share/wordlists/rockyou.txt
  
  # Crack with rules
  ./kerbcracker.py -i hashes.txt -w wordlist.txt -r /usr/share/hashcat/rules/best64.rule
  
  # Show already cracked hashes
  ./kerbcracker.py -i hashes.txt --show
  
  # Save results to file
  ./kerbcracker.py -i hashes.txt -w wordlist.txt -o cracked.txt
        """
    )
    
    parser.add_argument('-i', '--input', required=True, help='Input file containing Kerberos hashes')
    parser.add_argument('-w', '--wordlist', help='Wordlist for cracking', 
                       default='/usr/share/wordlists/rockyou.txt')
    parser.add_argument('-r', '--rules', help='Hashcat rules file')
    parser.add_argument('-o', '--output', help='Output file for cracked passwords')
    parser.add_argument('--show', action='store_true', help='Show already cracked hashes')
    
    args = parser.parse_args()
    
    cracker = KerbCracker()
    cracker.crack_all(args.input, args.wordlist, args.rules, args.output, args.show)

if __name__ == '__main__':
    main()
