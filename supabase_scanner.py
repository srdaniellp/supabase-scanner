#!/usr/bin/env python3

import requests
import json
import re
import os
import sys
import csv
from datetime import datetime
from urllib.parse import urlparse, quote
from typing import Optional, Dict, List

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", None)


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ____                   _                    ____
 / ___| _   _ _ __   __ _| |__   __ _ ___  ___/ ___|  ___ __ _ _ __  _ __   ___ _ __
 \\___ \\| | | | '_ \\ / _` | '_ \\ / _` / __|/ _ \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
  ___) | |_| | |_) | (_| | |_) | (_| \\__ \\  __/___) | (_| (_| | | | | | | |  __/ |
 |____/ \\__,_| .__/ \\__,_|_.__/ \\__,_|___/\\___|____/ \\___\\__,_|_| |_|_| |_|\\___|_|
             |_|
{Colors.END}
{Colors.YELLOW}    [ Supabase RLS Security Scanner ]{Colors.END}
"""
    print(banner)


def print_status(msg: str, status: str = "info"):
    icons = {
        "info": f"{Colors.BLUE}[*]{Colors.END}",
        "success": f"{Colors.GREEN}[+]{Colors.END}",
        "warning": f"{Colors.YELLOW}[!]{Colors.END}",
        "error": f"{Colors.RED}[-]{Colors.END}",
        "critical": f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.END}",
        "found": f"{Colors.GREEN}{Colors.BOLD}[FOUND]{Colors.END}",
    }
    print(f"{icons.get(status, icons['info'])} {msg}")


def search_github_for_supabase(domain: str) -> Optional[Dict[str, str]]:
    print_status(f"Searching GitHub for: {domain}", "info")

    parsed = urlparse(domain if domain.startswith("http") else f"https://{domain}")
    hostname = parsed.netloc or parsed.path

    search_terms = []
    parts = hostname.replace("www.", "").split(".")
    if len(parts) >= 2:
        search_terms.append(parts[0])
        search_terms.append(".".join(parts[:-1]))
    search_terms.append(hostname)

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SupabaseScanner/1.0"
    }

    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    queries = [
        f'repo:{search_terms[0]} supabase.co eyJhbGci',
        f'org:{search_terms[0]} supabase.co eyJhbGci',
        f'"{hostname}" supabase.co eyJhbGci',
        f'"{search_terms[0]}" SUPABASE_URL eyJhbGci extension:ts',
        f'"{search_terms[0]}" SUPABASE_URL eyJhbGci extension:js',
        f'"{search_terms[0]}" supabaseUrl eyJhbGci',
    ]

    found_results = []

    for query in queries:
        try:
            url = f"https://api.github.com/search/code?q={quote(query)}&per_page=5"
            r = requests.get(url, headers=headers, timeout=15)

            if r.status_code == 200:
                results = r.json().get("items", [])

                for item in results:
                    repo = item.get("repository", {}).get("full_name", "")
                    file_path = item.get("path", "")

                    repo_lower = repo.lower()
                    domain_name = search_terms[0].lower()

                    relevance = 0
                    if domain_name in repo_lower:
                        relevance = 10
                    elif any(term.lower() in repo_lower for term in search_terms):
                        relevance = 5

                    if relevance > 0:
                        print_status(f"Checking: {repo}/{file_path} (relevance: {relevance})", "info")

                        try:
                            content_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
                            cr = requests.get(content_url, headers={**headers, "Accept": "application/vnd.github.v3.raw"}, timeout=10)

                            if cr.status_code == 200:
                                content = cr.text

                                url_match = re.search(r'https://([a-z0-9]+)\.supabase\.co', content)
                                key_match = re.search(r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', content)

                                if url_match and key_match:
                                    supabase_url = f"https://{url_match.group(1)}.supabase.co"
                                    anon_key = key_match.group(1)

                                    found_results.append({
                                        "url": supabase_url,
                                        "key": anon_key,
                                        "source": f"github:{repo}/{file_path}",
                                        "relevance": relevance
                                    })

                        except:
                            continue

            elif r.status_code == 403:
                print_status("GitHub rate limit reached", "warning")
                break

        except:
            continue

    if found_results:
        best = max(found_results, key=lambda x: x["relevance"])
        print_status(f"Found in: {best['source']}", "found")
        print_status(f"URL: {best['url']}", "success")
        print_status(f"Key: {best['key'][:50]}...", "success")
        return best

    return None


def search_github_by_project_ref(project_ref: str) -> Optional[Dict[str, str]]:
    print_status(f"Searching key for project ref: {project_ref}", "info")

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "SupabaseScanner/1.0"
    }

    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    queries = [
        f'{project_ref}.supabase.co eyJhbGci',
        f'{project_ref} supabase anon',
        f'supabase {project_ref} createClient',
    ]

    for query in queries:
        try:
            url = f"https://api.github.com/search/code?q={quote(query)}&per_page=10"
            r = requests.get(url, headers=headers, timeout=15)

            if r.status_code == 200:
                results = r.json().get("items", [])

                for item in results:
                    repo = item.get("repository", {}).get("full_name", "")
                    file_path = item.get("path", "")

                    try:
                        content_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
                        cr = requests.get(content_url, headers={**headers, "Accept": "application/vnd.github.v3.raw"}, timeout=10)

                        if cr.status_code == 200:
                            content = cr.text

                            if project_ref in content:
                                key_match = re.search(r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', content)

                                if key_match:
                                    anon_key = key_match.group(1)
                                    print_status(f"Key found in: {repo}/{file_path}", "found")
                                    return {"key": anon_key, "source": f"github:{repo}/{file_path}"}
                    except:
                        continue

        except:
            continue

    return None


def extract_supabase_from_url(url: str) -> Optional[Dict[str, str]]:
    print_status(f"Analyzing {url}...", "info")

    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        r = requests.get(url, headers=headers, timeout=15)
        content = r.text

        patterns = {
            "url": [
                r'https://([a-z0-9]+)\.supabase\.co',
                r'SUPABASE_URL["\s:=]+["\']?(https://[a-z0-9]+\.supabase\.co)',
                r'supabaseUrl["\s:=]+["\']?(https://[a-z0-9]+\.supabase\.co)',
            ],
            "key": [
                r'(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
            ]
        }

        supabase_url = None
        anon_key = None

        for pattern in patterns["url"]:
            match = re.search(pattern, content)
            if match:
                if "supabase.co" in match.group(0):
                    supabase_url = match.group(0) if match.group(0).startswith("https") else f"https://{match.group(1)}.supabase.co"
                break

        for pattern in patterns["key"]:
            match = re.search(pattern, content)
            if match:
                anon_key = match.group(1)
                break

        if not supabase_url or not anon_key:
            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', content)
            for js_file in js_files[:10]:
                if not js_file.startswith("http"):
                    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    js_file = f"{base_url}/{js_file.lstrip('/')}"

                try:
                    js_content = requests.get(js_file, headers=headers, timeout=10).text

                    if not supabase_url:
                        for pattern in patterns["url"]:
                            match = re.search(pattern, js_content)
                            if match:
                                supabase_url = match.group(0) if match.group(0).startswith("https") else f"https://{match.group(1)}.supabase.co"
                                break

                    if not anon_key:
                        for pattern in patterns["key"]:
                            match = re.search(pattern, js_content)
                            if match:
                                anon_key = match.group(1)
                                break

                    if supabase_url and anon_key:
                        break
                except:
                    continue

        if supabase_url and anon_key:
            return {"url": supabase_url, "key": anon_key}
        elif supabase_url:
            print_status(f"URL found: {supabase_url}", "warning")
            print_status("Anon key not found automatically", "warning")
            return {"url": supabase_url, "key": None}

        return None

    except Exception as e:
        print_status(f"Error analyzing URL: {e}", "error")
        return None


def get_target_input() -> Dict[str, str]:
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}TARGET CONFIGURATION{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

    print("Input options:")
    print("  1. Website URL (e.g., https://example.com)")
    print("  2. Direct Supabase URL (e.g., https://abc123.supabase.co)")
    print("  3. Project Reference (e.g., abc123xyz)")
    print()
    print(f"{Colors.CYAN}The scanner will try to extract the Anon Key automatically from the site and GitHub.{Colors.END}")
    print()

    target = input(f"{Colors.YELLOW}Target: {Colors.END}").strip()

    if not target:
        print_status("Target cannot be empty", "error")
        sys.exit(1)

    result = {"url": None, "key": None, "source": None}

    if ".supabase.co" in target:
        if not target.startswith("https://"):
            target = f"https://{target}"
        result["url"] = target
        print_status(f"Supabase URL detected: {target}", "success")

        project_ref = target.split("//")[1].split(".")[0]
        print()
        print_status("Searching Anon Key on GitHub...", "info")
        github_result = search_github_by_project_ref(project_ref)
        if github_result:
            result["key"] = github_result["key"]
            result["source"] = github_result.get("source")
            print_status("Anon Key found on GitHub!", "success")

    elif target.startswith("http") or "." in target:
        if not target.startswith("http"):
            target = f"https://{target}"
        print_status(f"Detected as website URL: {target}", "info")
        print()
        print_status("Step 1: Analyzing website source code...", "info")
        extracted = extract_supabase_from_url(target)

        if extracted:
            result["url"] = extracted["url"]
            result["key"] = extracted["key"]
            print_status(f"Supabase URL extracted: {result['url']}", "success")
            if result["key"]:
                print_status("Anon key extracted from site!", "success")
                result["source"] = "website"

        if not result["url"] or not result["key"]:
            print()
            print_status("Step 2: Searching on GitHub...", "info")
            github_result = search_github_for_supabase(target)

            if github_result:
                if not result["url"]:
                    result["url"] = github_result["url"]
                if not result["key"]:
                    result["key"] = github_result["key"]
                    result["source"] = github_result.get("source")
                print_status("Credentials found on GitHub!", "success")

        if not result["url"]:
            print()
            print_status("Could not find Supabase URL", "warning")
            manual_url = input(f"{Colors.YELLOW}Supabase URL (or Enter to exit): {Colors.END}").strip()
            if manual_url:
                if not manual_url.startswith("https://"):
                    manual_url = f"https://{manual_url}"
                result["url"] = manual_url
            else:
                sys.exit(1)

    else:
        result["url"] = f"https://{target}.supabase.co"
        print_status(f"URL built: {result['url']}", "info")

        print()
        print_status("Searching Anon Key on GitHub...", "info")
        github_result = search_github_by_project_ref(target)
        if github_result:
            result["key"] = github_result["key"]
            result["source"] = github_result.get("source")
            print_status("Anon Key found on GitHub!", "success")

    if not result["key"]:
        print()
        print_status("Anon Key not found automatically", "warning")
        print(f"\n{Colors.CYAN}Where to find the Anon Key:{Colors.END}")
        print("  - DevTools (F12) > Network > filter 'supabase' > check header 'apikey'")
        print("  - View Source (Ctrl+U) > search 'eyJhbGci' or 'SUPABASE'")
        print("  - Project's GitHub > files .env, config.ts, supabase.ts")
        print()
        anon_key = input(f"{Colors.YELLOW}Anon Key (JWT): {Colors.END}").strip()
        if not anon_key:
            print_status("Anon key is required to continue", "error")
            sys.exit(1)
        result["key"] = anon_key
        result["source"] = "manual"

    print()
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}SUMMARY{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"  URL: {result['url']}")
    print(f"  Key: {result['key'][:50]}...")
    print(f"  Source: {result.get('source', 'N/A')}")

    return result


class SupabaseScanner:
    def __init__(self, url: str, anon_key: str):
        self.url = url.rstrip("/")
        self.anon_key = anon_key
        self.headers = {
            "apikey": anon_key,
            "Authorization": f"Bearer {anon_key}",
            "Content-Type": "application/json"
        }
        self.tables_found = []
        self.rls_status = "unknown"
        self.write_access = False
        self.dump_dir = None

        self.common_tables = [
            "users", "profiles", "accounts", "auth_users", "members", "customers",
            "admins", "administrators", "staff", "employees", "roles", "permissions",
            "sessions", "tokens", "refresh_tokens", "api_keys", "credentials",
            "posts", "articles", "pages", "content", "documents", "files", "uploads",
            "images", "media", "attachments", "comments", "reviews", "feedback",
            "messages", "emails", "notifications", "alerts", "newsletters",
            "subscribers", "contacts", "leads", "conversations", "chats",
            "orders", "products", "items", "inventory", "cart", "checkout",
            "payments", "transactions", "invoices", "subscriptions", "plans",
            "projects", "tasks", "tickets", "issues", "reports", "analytics",
            "logs", "events", "activities", "audit_logs", "history",
            "settings", "config", "configurations", "preferences", "options",
            "locations", "addresses", "places", "coordinates", "markers", "routes",
            "likes", "votes", "ratings", "reactions", "follows", "friends",
            "connections", "shares", "bookmarks", "favorites",
            "data", "records", "entries", "categories", "tags", "metadata",
        ]

    def check_connection(self) -> bool:
        try:
            r = requests.get(f"{self.url}/rest/v1/", headers=self.headers, timeout=10)
            if r.status_code in [200, 401, 406]:
                print_status(f"Connection OK (Status: {r.status_code})", "success")
                return True
            else:
                print_status(f"Unexpected response: {r.status_code}", "warning")
                return True
        except requests.exceptions.ConnectionError:
            print_status("Instance offline or does not exist", "error")
            return False
        except Exception as e:
            print_status(f"Connection error: {e}", "error")
            return False

    def enumerate_tables(self) -> List[Dict]:
        print_status("Enumerating tables...", "info")

        found = []
        for table in self.common_tables:
            try:
                r = requests.get(
                    f"{self.url}/rest/v1/{table}?select=*&limit=1",
                    headers=self.headers,
                    timeout=5
                )

                if r.status_code == 200:
                    data = r.json()
                    if data:
                        count_headers = {**self.headers, "Prefer": "count=exact"}
                        cr = requests.get(
                            f"{self.url}/rest/v1/{table}?select=count",
                            headers=count_headers,
                            timeout=5
                        )
                        total = cr.headers.get("content-range", "?").split("/")[-1]

                        found.append({
                            "table": table,
                            "columns": list(data[0].keys()),
                            "sample": data[0],
                            "total": total
                        })
                        print_status(f"TABLE: {table} ({total} rows)", "found")
                    elif r.text == "[]":
                        found.append({
                            "table": table,
                            "columns": [],
                            "sample": None,
                            "total": "0"
                        })
            except:
                continue

        self.tables_found = found
        return found

    def test_write_access(self) -> Dict[str, bool]:
        print_status("Testing write access...", "info")

        results = {"insert": False, "update": False, "delete": False}

        if not self.tables_found:
            print_status("No tables to test write access", "info")
            return results

        for table_info in self.tables_found:
            table = table_info["table"]
            columns = table_info.get("columns", [])

            try:
                if columns and "email" in columns:
                    test_data = {"email": f"rls_test_{datetime.now().strftime('%H%M%S')}@test.local"}
                elif columns and "name" in columns:
                    test_data = {"name": f"rls_test_{datetime.now().strftime('%H%M%S')}"}
                else:
                    test_data = {}

                r = requests.post(
                    f"{self.url}/rest/v1/{table}",
                    headers=self.headers,
                    json=test_data,
                    timeout=5
                )

                if r.status_code == 201:
                    results["insert"] = True
                    print_status(f"INSERT allowed on '{table}'!", "critical")

                    try:
                        inserted = r.json()
                        if inserted and isinstance(inserted, list) and len(inserted) > 0:
                            record_id = inserted[0].get("id")
                            if record_id:
                                dr = requests.delete(
                                    f"{self.url}/rest/v1/{table}?id=eq.{record_id}",
                                    headers=self.headers,
                                    timeout=5
                                )
                                if dr.status_code in [200, 204]:
                                    results["delete"] = True
                                    print_status(f"DELETE allowed on '{table}'!", "critical")
                    except:
                        pass
                    break

                elif r.status_code == 409:
                    print_status(f"Partial INSERT on '{table}' (conflict)", "warning")

                elif r.status_code in [401, 403]:
                    print_status(f"INSERT blocked on '{table}' (RLS OK)", "info")

            except:
                continue

        if not any(results.values()):
            print_status("No write access detected", "success")

        self.write_access = any(results.values())
        return results

    def check_storage_buckets(self) -> List[Dict]:
        print_status("Checking storage buckets...", "info")

        try:
            r = requests.get(
                f"{self.url}/storage/v1/bucket",
                headers=self.headers,
                timeout=10
            )

            if r.status_code == 200:
                buckets = r.json()
                if buckets:
                    print_status(f"Found {len(buckets)} buckets", "found")
                    for b in buckets:
                        status = "PUBLIC" if b.get("public") else "private"
                        print(f"      - {b.get('name')}: {status}")
                    return buckets
            return []
        except:
            return []

    def check_rpc_functions(self) -> List[str]:
        print_status("Checking RPC functions...", "info")

        common_rpcs = [
            "get_user", "get_users", "create_user", "delete_user",
            "get_profile", "update_profile", "search", "query",
            "execute", "run", "admin", "export", "import"
        ]

        found = []
        for rpc in common_rpcs:
            try:
                r = requests.post(
                    f"{self.url}/rest/v1/rpc/{rpc}",
                    headers=self.headers,
                    json={},
                    timeout=5
                )
                if r.status_code != 404:
                    found.append(rpc)
                    print_status(f"RPC: {rpc} (status: {r.status_code})", "found")
            except:
                continue

        return found

    def determine_rls_status(self) -> str:
        if not self.tables_found:
            self.rls_status = "enabled"
            return "enabled"

        if self.write_access:
            self.rls_status = "disabled"
            return "disabled"

        sensitive_tables = ["users", "profiles", "accounts", "customers", "subscribers",
                          "emails", "payments", "orders", "credentials", "tokens"]

        has_sensitive = any(t["table"] in sensitive_tables for t in self.tables_found)

        if has_sensitive:
            self.rls_status = "partial"
            return "partial"

        self.rls_status = "partial"
        return "partial"

    def dump_table(self, table: str, limit: int = 1000) -> List[Dict]:
        try:
            r = requests.get(
                f"{self.url}/rest/v1/{table}?select=*&limit={limit}",
                headers=self.headers,
                timeout=30
            )
            if r.status_code == 200:
                return r.json()
            return []
        except:
            return []

    def dump_all_tables(self, output_dir: str = None) -> str:
        if not output_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            project_ref = self.url.split("//")[1].split(".")[0]
            output_dir = f"supabase_dump_{project_ref}_{timestamp}"

        os.makedirs(output_dir, exist_ok=True)
        self.dump_dir = output_dir

        print_status(f"Saving dumps to: {output_dir}/", "info")

        summary = {
            "target": self.url,
            "scan_time": datetime.now().isoformat(),
            "rls_status": self.rls_status,
            "write_access": self.write_access,
            "tables": []
        }

        for table_info in self.tables_found:
            table = table_info["table"]
            print_status(f"Dumping {table}...", "info")

            data = self.dump_table(table)

            if data:
                with open(f"{output_dir}/{table}.json", "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, default=str, ensure_ascii=False)

                if data and isinstance(data[0], dict):
                    with open(f"{output_dir}/{table}.csv", "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=data[0].keys())
                        writer.writeheader()
                        writer.writerows(data)

                summary["tables"].append({
                    "name": table,
                    "rows": len(data),
                    "columns": list(data[0].keys()) if data else []
                })

                print_status(f"  {table}: {len(data)} records saved", "success")

        with open(f"{output_dir}/SUMMARY.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        return output_dir

    def generate_report(self) -> str:
        report = []
        report.append("\n" + "="*70)
        report.append(f"{Colors.BOLD}SUPABASE ANALYSIS REPORT{Colors.END}")
        report.append("="*70)

        report.append(f"\n{Colors.CYAN}Target:{Colors.END} {self.url}")
        report.append(f"{Colors.CYAN}Date:{Colors.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        report.append(f"\n{Colors.CYAN}{'='*50}{Colors.END}")
        report.append(f"{Colors.BOLD}RLS STATUS{Colors.END}")
        report.append(f"{Colors.CYAN}{'='*50}{Colors.END}")

        if self.rls_status == "disabled":
            report.append(f"\n{Colors.RED}{Colors.BOLD}[CRITICAL] RLS DISABLED!{Colors.END}")
            report.append(f"{Colors.RED}Full read/write access available{Colors.END}")
        elif self.rls_status == "partial":
            report.append(f"\n{Colors.YELLOW}{Colors.BOLD}[WARNING] RLS PARTIALLY CONFIGURED{Colors.END}")
            report.append(f"{Colors.YELLOW}Some tables are exposed{Colors.END}")
        else:
            report.append(f"\n{Colors.GREEN}{Colors.BOLD}[OK] RLS PROPERLY CONFIGURED{Colors.END}")
            report.append(f"{Colors.GREEN}No exposed tables found{Colors.END}")

        if self.tables_found:
            report.append(f"\n{Colors.CYAN}{'='*50}{Colors.END}")
            report.append(f"{Colors.BOLD}EXPOSED TABLES ({len(self.tables_found)}){Colors.END}")
            report.append(f"{Colors.CYAN}{'='*50}{Colors.END}")

            for t in self.tables_found:
                report.append(f"\n{Colors.GREEN}>> {t['table']}{Colors.END} ({t['total']} records)")
                report.append(f"   Columns: {', '.join(t['columns'][:10])}")
                if len(t['columns']) > 10:
                    report.append(f"            ... +{len(t['columns'])-10} more")

                if t['sample']:
                    report.append(f"   Sample: {json.dumps(t['sample'], default=str)[:200]}...")

        if self.write_access:
            report.append(f"\n{Colors.RED}{'='*50}{Colors.END}")
            report.append(f"{Colors.RED}{Colors.BOLD}WRITE ACCESS AVAILABLE!{Colors.END}")
            report.append(f"{Colors.RED}INSERT/UPDATE/DELETE allowed{Colors.END}")
            report.append(f"{Colors.RED}{'='*50}{Colors.END}")

        if self.dump_dir:
            report.append(f"\n{Colors.CYAN}{'='*50}{Colors.END}")
            report.append(f"{Colors.BOLD}DUMP SAVED{Colors.END}")
            report.append(f"{Colors.CYAN}{'='*50}{Colors.END}")
            report.append(f"\nDirectory: {self.dump_dir}/")

        return "\n".join(report)

    def run_full_scan(self):
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}STARTING ANALYSIS{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

        if not self.check_connection():
            return

        print()

        self.enumerate_tables()

        if not self.tables_found:
            print_status("No accessible tables found", "success")
            print_status("RLS appears to be properly configured", "success")
            self.rls_status = "enabled"
            print(self.generate_report())
            return

        print()

        self.test_write_access()

        print()

        self.check_storage_buckets()

        print()

        self.check_rpc_functions()

        self.determine_rls_status()

        if self.rls_status in ["disabled", "partial"]:
            print()
            print(f"{Colors.YELLOW}{'='*60}{Colors.END}")
            do_dump = input(f"{Colors.YELLOW}Do you want to dump all tables? (y/N): {Colors.END}").strip().lower()

            if do_dump == 'y':
                self.dump_all_tables()

        print(self.generate_report())

        if self.dump_dir:
            report_path = f"{self.dump_dir}/REPORT.txt"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            project_ref = self.url.split("//")[1].split(".")[0]
            report_path = f"supabase_report_{project_ref}_{timestamp}.txt"

        report_clean = self.generate_report()
        for color in [Colors.RED, Colors.GREEN, Colors.YELLOW, Colors.BLUE,
                      Colors.MAGENTA, Colors.CYAN, Colors.WHITE, Colors.BOLD, Colors.END]:
            report_clean = report_clean.replace(color, "")

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_clean)

        print(f"\n{Colors.GREEN}Report saved to: {report_path}{Colors.END}")


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_menu() -> int:
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}SCAN COMPLETED{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")

    print(f"{Colors.YELLOW}What would you like to do?{Colors.END}")
    print(f"  {Colors.GREEN}1{Colors.END} - New scan")
    print(f"  {Colors.RED}2{Colors.END} - Exit")
    print()

    while True:
        choice = input(f"{Colors.YELLOW}Option: {Colors.END}").strip()
        if choice == "1":
            return 1
        elif choice == "2":
            return 2
        else:
            print_status("Invalid option. Enter 1 or 2.", "warning")


def run_scan():
    target = get_target_input()
    scanner = SupabaseScanner(target["url"], target["key"])
    scanner.run_full_scan()
    return show_menu()


def main():
    while True:
        clear_screen()
        print_banner()

        choice = run_scan()

        if choice == 2:
            print(f"\n{Colors.GREEN}Goodbye!{Colors.END}\n")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan cancelled by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}")
        sys.exit(1)
