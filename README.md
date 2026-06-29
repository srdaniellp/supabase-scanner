# Supabase Scanner

A security assessment tool for analyzing Row Level Security (RLS) configurations in Supabase instances.

```
  ____                   _                    ____
 / ___| _   _ _ __   __ _| |__   __ _ ___  ___/ ___|  ___ __ _ _ __  _ __   ___ _ __
 \___ \| | | | '_ \ / _` | '_ \ / _` / __|/ _ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ___) | |_| | |_) | (_| | |_) | (_| \__ \  __/___) | (_| (_| | | | | | | |  __/ |
 |____/ \__,_| .__/ \__,_|_.__/ \__,_|___/\___|____/ \___\__,_|_| |_|_| |_|\___|_|
             |_|
```

## Features

- **Automatic Credential Discovery**: Extracts Supabase URL and Anon Key from websites and GitHub repositories
- **Table Enumeration**: Discovers accessible tables through the PostgREST API
- **RLS Status Detection**: Identifies disabled, partial, or properly configured RLS
- **Write Access Testing**: Tests for INSERT/UPDATE/DELETE permissions
- **Storage Bucket Analysis**: Lists storage buckets and their visibility settings
- **RPC Function Discovery**: Enumerates accessible RPC functions
- **Data Export**: Dumps exposed data to JSON and CSV formats
- **Detailed Reports**: Generates comprehensive security assessment reports

## Installation

```bash
git clone https://github.com/srdaniellp/supabase-scanner.git
cd supabase-scanner
pip install -r requirements.txt
```

## Usage

```bash
python supabase_scanner.py
```

### Input Options

The scanner accepts three types of input:

1. **Website URL**: `https://example.com` - Automatically extracts Supabase credentials from the site
2. **Direct Supabase URL**: `https://abc123.supabase.co` - Uses the provided project URL
3. **Project Reference**: `abc123xyz` - Builds the URL automatically

### Environment Variables

For better GitHub search results (higher rate limits), set your GitHub token:

```bash
export GITHUB_TOKEN=your_github_token
```

## Output

### Console Report

The scanner provides a detailed console report including:
- RLS status (disabled/partial/enabled)
- List of exposed tables with row counts
- Write access status
- Storage buckets visibility
- Available RPC functions

### File Output

- `supabase_report_<project>_<timestamp>.txt` - Text report
- `supabase_dump_<project>_<timestamp>/` - Directory with:
  - `<table>.json` - JSON dump of each table
  - `<table>.csv` - CSV dump of each table
  - `SUMMARY.json` - Scan summary

## Example

```
$ python supabase_scanner.py

Target: https://example.com

[*] Step 1: Analyzing website source code...
[+] Supabase URL extracted: https://abc123.supabase.co
[+] Anon key extracted from site!

[*] Starting analysis...
[+] Connection OK (Status: 200)
[*] Enumerating tables...
[FOUND] TABLE: users (1523 rows)
[FOUND] TABLE: profiles (1520 rows)
[*] Testing write access...
[+] No write access detected

======================================================================
SUPABASE ANALYSIS REPORT
======================================================================

Target: https://abc123.supabase.co
Date: 2024-01-15 14:30:00

[WARNING] RLS PARTIALLY CONFIGURED
Some tables are exposed

EXPOSED TABLES (2)
>> users (1523 records)
   Columns: id, email, created_at...
```

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before testing any systems you do not own. The authors are not responsible for any misuse or damage caused by this tool.

## License

MIT License - see [LICENSE](LICENSE) for details.
