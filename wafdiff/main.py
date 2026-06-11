import argparse
import requests
import urllib3
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

BANNER = r"""
 __        __    _  __ ____  _  __  __ 
 \ \      / /_ _| |/ /|  _ \(_)/ _|/ _|
  \ \ /\ / / _` | ' / | | | | | |_| |_ 
   \ V  V / (_| | . \ | |_| | |  _|  _|
    \_/\_/ \__,_|_|\_\|____/|_|_| |_|  
                                       
    WAF Inconsistency Detector & Payload Differ
    Made by baba01hacker
"""

DEFAULT_PAYLOADS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "${jndi:ldap://127.0.0.1/a}",
    "UNION SELECT 1,2,3",
    "../../../../windows/win.ini",
    "javascript://%250Aalert(1)",
    "'; EXEC xp_cmdshell('ping 127.0.0.1');--"
]

class WafDiff:
    def __init__(self, args):
        self.base_url = args.url.rstrip('/')
        self.paths = args.paths
        self.payloads = args.payloads if args.payloads else DEFAULT_PAYLOADS
        self.method = args.method.upper()
        
        self.threads = args.threads
        self.timeout = args.timeout
        self.delay = args.delay
        
        self.verify_ssl = not args.insecure
        self.proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        
        self.headers = {"User-Agent": args.user_agent or "WafDiff-Probe/2.0"}
        if args.headers:
            for h in args.headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.headers[k.strip()] = v.strip()
                    
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        if self.proxies:
            self.session.proxies.update(self.proxies)

    def print_msg(self, level, msg):
        if level == "success":
            print(f"{Colors.OKGREEN}[+]{Colors.ENDC} {msg}")
        elif level == "info":
            print(f"{Colors.OKBLUE}[*]{Colors.ENDC} {msg}")
        elif level == "warning":
            print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")
        elif level == "error":
            print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}")

    def test_payload(self, path, payload):
        if self.delay > 0:
            time.sleep(self.delay)
            
        target_url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            req_kwargs = {
                "timeout": self.timeout,
                "verify": self.verify_ssl,
                "allow_redirects": False
            }
            
            if self.method == "GET":
                req_kwargs["params"] = {"q": payload}
            else:
                req_kwargs["data"] = {"data": payload}
                
            resp = self.session.request(self.method, target_url, **req_kwargs)
            return {
                "url": target_url, 
                "path": path, 
                "payload": payload, 
                "status": resp.status_code, 
                "length": len(resp.content), 
                "error": None
            }
        except requests.exceptions.RequestException as e:
            return {
                "url": target_url, 
                "path": path, 
                "payload": payload, 
                "status": 0, 
                "length": 0, 
                "error": str(e)
            }

    def run(self):
        print(Colors.OKCYAN + BANNER.replace("baba01hacker", f"{Colors.BOLD}baba01hacker{Colors.ENDC}{Colors.OKCYAN}") + Colors.ENDC)
        self.print_msg("info", f"Target Base: {Colors.BOLD}{self.base_url}{Colors.ENDC}")
        self.print_msg("info", f"Testing {len(self.paths)} paths with {len(self.payloads)} payloads via {self.method}")
        self.print_msg("info", f"Threads: {self.threads} | Timeout: {self.timeout}s")
        print("-" * 60)
        
        results = []
        total_tasks = len(self.payloads) * len(self.paths)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for payload in self.payloads:
                for path in self.paths:
                    futures.append(executor.submit(self.test_payload, path, payload))
                    
            for future in as_completed(futures):
                res = future.result()
                results.append(res)
                completed += 1
                sys.stdout.write(f"\r{Colors.OKCYAN}[>]{Colors.ENDC} Progress: {completed}/{total_tasks} requests completed.")
                sys.stdout.flush()

        print("\n" + "-" * 60)
        
        # Group by payload to analyze inconsistencies
        grouped = {}
        for r in results:
            p = r["payload"]
            if p not in grouped:
                grouped[p] = []
            grouped[p].append(r)
            
        inconsistencies_found = 0
            
        for p, items in grouped.items():
            print(f"\n{Colors.BOLD}Payload:{Colors.ENDC} {p}")
            valid_items = [item for item in items if not item["error"]]
            statuses = set(item["status"] for item in valid_items)
            lengths = set(item["length"] for item in valid_items)
            
            if len(statuses) > 1:
                self.print_msg("warning", f"INCONSISTENT BLOCKING DETECTED! Status Codes: {list(statuses)}")
                inconsistencies_found += 1
            elif len(statuses) == 1 and len(lengths) > 1:
                self.print_msg("warning", f"INCONSISTENT RESPONSE LENGTHS! Status: {list(statuses)[0]} | Lengths: {list(lengths)}")
                inconsistencies_found += 1
            elif len(statuses) == 1:
                self.print_msg("info", f"Consistent behavior globally. Status: {list(statuses)[0]}, Length: {list(lengths)[0]}")
            else:
                self.print_msg("error", "Failed to receive valid responses across all paths.")
                
            # Detail print
            for item in items:
                if item["error"]:
                    print(f"    {Colors.FAIL}✖{Colors.ENDC} {item['path']:<15} | ERROR: {item['error']}")
                else:
                    color = Colors.OKGREEN if item['status'] in [200, 201, 301, 302] else Colors.WARNING
                    print(f"    {color}✔{Colors.ENDC} {item['path']:<15} | HTTP {item['status']:<4} | Size: {item['length']}")

        print("-" * 60)
        if inconsistencies_found > 0:
            self.print_msg("success", f"Scan complete! Found {inconsistencies_found} payloads with inconsistent WAF behavior.")
        else:
            self.print_msg("info", "Scan complete. WAF behavior appears uniform across tested paths.")

def main():
    parser = argparse.ArgumentParser(description="WafDiff - Advanced WAF Inconsistency Detector")
    
    # Required
    parser.add_argument("-u", "--url", required=True, help="Base URL to test (e.g., https://example.com)")
    parser.add_argument("-p", "--paths", nargs="+", default=["/", "/api/", "/login", "/search", "/graphql", "/admin"], help="Paths to test (space separated)")
    parser.add_argument("--payloads", nargs="+", help="Custom payloads to test (space separated)")
    
    # Request config
    req_group = parser.add_argument_group("Request Options")
    req_group.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    req_group.add_argument("-H", "--headers", nargs="*", help="Custom headers")
    req_group.add_argument("-A", "--user-agent", help="Custom User-Agent string")
    req_group.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    
    # Performance & Evasion
    net_group = parser.add_argument_group("Performance & Evasion")
    net_group.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    net_group.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    net_group.add_argument("-x", "--proxy", help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    net_group.add_argument("-k", "--insecure", action="store_true", help="Disable SSL/TLS certificate verification")

    args = parser.parse_args()
    
    try:
        wd = WafDiff(args)
        wd.run()
    except KeyboardInterrupt:
        print("\n")
        print(f"{Colors.WARNING}[!]{Colors.ENDC} Interrupted by user. Exiting safely.")
        sys.exit(0)

if __name__ == "__main__":
    main()
