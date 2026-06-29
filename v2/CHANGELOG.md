# Changelog

All notable changes to Supabase RLS Scanner will be documented in this file.

## [2.0.0] - 2026-06-30

### Added

- **Service Role Escalation**: Automatically hunts for `service_role` keys in source repositories
- **Full Database Dump**: When service_role is found, dumps ALL tables (not just common ones)
- **Auth Admin API Access**: Extracts all users from `auth.users` with metadata
- **Storage Enumeration**: Lists all objects in private storage buckets
- **Auth Settings Extraction**: Retrieves authentication configuration
- **Improved GitHub Search**: Two-phase search with repository prioritization
  - Phase 1: Searches repositories by name, prioritizes originals over forks
  - Phase 2: Falls back to code search if no results
- **Repository Scoring**: Ranks repositories by relevance (stars, activity, fork status)
- **Multiple Input Types**: Website URL, Supabase URL, project reference, or GitHub repo
- **Simplified Dump Names**: Uses repository name instead of project reference hash
- **Progress Tracking**: Shows progress during table enumeration

### Changed

- Migrated from hardcoded tokens to environment variables (`GITHUB_TOKEN`)
- Improved table enumeration with 80+ common table names
- Better placeholder detection (ignores `app`, `example`, `xxx`, etc.)
- Cleaner output formatting with color-coded status messages
- English interface (previously Portuguese)

### Fixed

- Rate limit handling for GitHub API
- Connection timeout handling
- JSON serialization of datetime objects
- CSV export with proper encoding

### Security

- Removed all hardcoded credentials
- Token loaded from environment variable only
- No sensitive data in source code

## [1.0.0] - 2026-05-01

### Initial Release

- Basic RLS vulnerability scanning
- Table enumeration
- Write access testing
- Storage bucket discovery
- RPC function enumeration
- JSON/CSV dump export
- GitHub credential search
