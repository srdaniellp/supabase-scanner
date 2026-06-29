# Supabase RLS Scanner v2.0

Security scanner for detecting Row Level Security (RLS) misconfigurations in Supabase instances.

## Features

- **Automatic credential discovery** from websites, GitHub repositories, and project references
- **RLS vulnerability detection** - identifies disabled or partially configured RLS
- **Write access testing** - tests INSERT/UPDATE/DELETE permissions
- **Storage bucket enumeration** - discovers public and private buckets
- **RPC function discovery** - finds exposed RPC endpoints
- **Service role escalation** - hunts for service_role keys and performs full database dump
- **Comprehensive reporting** - generates detailed JSON and text reports

## Installation

```bash
# Clone the repository
git clone https://github.com/srdaniellp/supabase-scanner.git
cd supabase-scanner

# Install dependencies
pip install requests
```

## GitHub Token Configuration

The scanner uses GitHub API to search for Supabase credentials in repositories. Without a token, you're limited to 10 requests per minute. With a token, you get 30 requests per minute.

### Creating a GitHub Token

1. Go to [GitHub Settings > Developer Settings > Personal Access Tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Give it a name (e.g., "supabase-scanner")
4. Select scope: `public_repo` (only needed for public repository access)
5. Click "Generate token"
6. Copy the token

### Setting the Token

**Linux/macOS:**
```bash
export GITHUB_TOKEN=ghp_your_token_here
python supabase_scanner.py
```

**Windows (PowerShell):**
```powershell
$env:GITHUB_TOKEN = "ghp_your_token_here"
python supabase_scanner.py
```

**Windows (CMD):**
```cmd
set GITHUB_TOKEN=ghp_your_token_here
python supabase_scanner.py
```

**Permanent (add to shell profile):**
```bash
# Add to ~/.bashrc or ~/.zshrc
export GITHUB_TOKEN=ghp_your_token_here
```

> **Note:** The scanner works without a token but with reduced rate limits. For scanning multiple targets, a token is recommended.

## Usage

```bash
python supabase_scanner.py
```

### Input Types

The scanner accepts multiple input formats:

1. **Website URL**: `https://example.com` - extracts credentials from source code
2. **Supabase URL**: `https://abc123.supabase.co` - searches GitHub for anon key
3. **Project Reference**: `abc123xyz` - constructs URL and searches for key
4. **GitHub Repository**: `user/repo` - extracts credentials directly

### Example Session

```
Target: https://example.com

[*] Phase 1: Analyzing website source code...
[+] Supabase URL extracted: https://abc123.supabase.co
[+] Anon key extracted from website!

============================================================
STARTING ANALYSIS
============================================================

[+] Connection OK (Status: 200)
[*] Enumerating tables...
[FOUND] TABLE: users (1523 rows)
[FOUND] TABLE: profiles (1520 rows)
[FOUND] TABLE: orders (8942 rows)

[*] Testing write access...
[CRITICAL] INSERT allowed on 'users'!
[CRITICAL] DELETE allowed on 'users'!

[*] Checking storage buckets...
[FOUND] Found 3 buckets
      - avatars: PUBLIC
      - documents: private
      - uploads: PUBLIC
```

## Output

### Dump Structure

```
dump/
└── project_0629_1430/
    ├── SUMMARY.json
    ├── REPORT.txt
    ├── users.json
    ├── users.csv
    ├── profiles.json
    ├── profiles.csv
    └── tables/           # (if service_role escalation)
        ├── table1.json
        ├── table2.json
        └── ...
```

### Escalation Data (service_role)

When a service_role key is found:

```
dump/
└── project_0629_1430/
    ├── auth_users.json        # All auth.users data
    ├── all_tables.txt         # List of all tables
    ├── auth_settings.json     # Auth configuration
    ├── storage_objects.json   # All storage objects
    ├── SERVICE_ROLE_KEY.txt   # The service_role key
    └── tables/                # Full dump of ALL tables
```

## RLS Status Levels

| Status | Description |
|--------|-------------|
| `enabled` | No tables accessible - RLS properly configured |
| `partial` | Some tables exposed but no write access |
| `disabled` | Full read/write access - critical vulnerability |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub personal access token for API requests (optional, improves rate limits) |

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any Supabase instance. Unauthorized access to computer systems is illegal.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

MIT License
