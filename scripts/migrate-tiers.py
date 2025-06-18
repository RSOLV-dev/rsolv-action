#!/usr/bin/env python3
"""
Pattern Tier Migration Script
Reorganizes patterns from 4-tier to 3-tier structure
"""

import re
import os
from pathlib import Path
from collections import defaultdict

# Pattern classification for new 3-tier structure
PUBLIC_PATTERNS = {
    # Basic XSS for demos
    "js-xss-innerhtml", "js-xss-document-write", "js-xss-jquery-html",
    "py-xss-template", "py-xss-format-string",
    "rb-xss-erb-raw", "rb-xss-haml-raw",
    "php-xss-echo", "php-xss-print",
    "ex-xss-raw", "ex-xss-safe-tuple",
    "java-xss-jsp-expression",
    
    # Basic educational patterns
    "js-weak-crypto-md5", "py-weak-crypto-md5", "rb-weak-crypto-md5",
    "java-weak-crypto-md5", "php-weak-crypto-md5",
    
    # Basic hardcoded secrets
    "js-hardcoded-secret-password", "py-hardcoded-password",
    "rb-hardcoded-password", "java-hardcoded-password",
    
    # Debug/info disclosure  
    "rails-debug-mode", "django-debug-true", "php-display-errors",
    "java-stack-trace-exposure", "ex-debug-info",
    
    # Basic open redirect
    "js-open-redirect", "py-open-redirect", "rb-open-redirect"
}

ENTERPRISE_PATTERNS = {
    # Pattern IDs that should be enterprise
}

# Regex patterns for enterprise classification
ENTERPRISE_REGEX = [
    r'cve-\d{4}-\d+',  # CVE patterns
    r'.*-rce$',  # Remote Code Execution
    r'.*-xxe-.*',  # XXE patterns
    r'.*pickle.*rce',  # Pickle RCE
    r'.*yaml.*rce',  # YAML RCE
    r'.*-ssti',  # Server-Side Template Injection
    r'.*template-injection',
    r'ldap-injection',
    r'xpath-injection',
    r'.*struts.*',  # Struts vulnerabilities
    r'.*spring.*rce',  # Spring vulnerabilities
    r'.*jackson.*poly',  # Jackson polymorphic
    r'race-condition',
    r'toctou',
    r'mass-assignment.*admin',
    r'.*traversal.*bypass'
]

def is_enterprise_pattern(pattern_id):
    """Check if pattern should be enterprise tier"""
    if pattern_id in ENTERPRISE_PATTERNS:
        return True
    
    for regex in ENTERPRISE_REGEX:
        if re.match(regex, pattern_id):
            return True
    
    return False

def determine_tier(pattern_id, current_tier):
    """Determine new tier for pattern"""
    if pattern_id in PUBLIC_PATTERNS:
        return "public"
    elif is_enterprise_pattern(pattern_id):
        return "enterprise"
    else:
        return "ai"  # Professional tier

def migrate_file(filepath):
    """Migrate a single pattern file"""
    print(f"\n📄 Processing {os.path.basename(filepath)}...")
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Track stats
    stats = defaultdict(int)
    current_pattern_id = None
    
    # Process line by line
    lines = content.split('\n')
    updated_lines = []
    
    for i, line in enumerate(lines):
        # Extract pattern ID
        id_match = re.search(r'id:\s*"([^"]+)"', line)
        if id_match:
            current_pattern_id = id_match.group(1)
            stats['total'] += 1
        
        # Update tier assignment
        tier_match = re.search(r'default_tier:\s*"([^"]+)"', line)
        if tier_match and current_pattern_id:
            old_tier = tier_match.group(1)
            new_tier = determine_tier(current_pattern_id, old_tier)
            
            if old_tier != new_tier:
                line = re.sub(r'default_tier:\s*"[^"]+"', f'default_tier: "{new_tier}"', line)
                stats['migrated'] += 1
                print(f"   📝 {current_pattern_id}: {old_tier} → {new_tier}")
            
            stats[new_tier] += 1
        
        updated_lines.append(line)
    
    # Write updated content
    with open(filepath, 'w') as f:
        f.write('\n'.join(updated_lines))
    
    return stats

def main():
    """Main migration function"""
    print("🚀 Starting Pattern Tier Migration")
    print("==================================")
    print("\nMigrating to 3-tier structure:")
    print("  • Public (Free/Demo): Basic patterns for demos")
    print("  • AI (Professional): Most security patterns")  
    print("  • Enterprise: Advanced patterns, CVEs")
    
    # Find pattern files
    pattern_dir = Path(__file__).parent.parent / 'lib' / 'rsolv_api' / 'security' / 'patterns'
    pattern_files = list(pattern_dir.glob('*.ex'))
    
    if not pattern_files:
        print(f"❌ No pattern files found in {pattern_dir}")
        return
    
    # Process each file
    total_stats = defaultdict(int)
    
    for filepath in pattern_files:
        if filepath.name == 'pattern_loader.ex':
            continue
            
        stats = migrate_file(filepath)
        
        # Aggregate stats
        for key, value in stats.items():
            total_stats[key] += value
    
    # Print summary
    print("\n" + "="*50)
    print("📊 Migration Summary")
    print("="*50)
    print(f"Total patterns: {total_stats['total']}")
    print(f"Patterns migrated: {total_stats['migrated']}")
    print(f"\nNew Distribution:")
    print(f"  🆓 Public tier: {total_stats['public']} patterns")
    print(f"  💼 AI tier: {total_stats['ai']} patterns") 
    print(f"  🏢 Enterprise tier: {total_stats['enterprise']} patterns")
    print(f"\n✅ Migration complete!")
    
    # Create summary file
    summary_path = Path(__file__).parent / 'tier-migration-summary.md'
    with open(summary_path, 'w') as f:
        f.write("# Pattern Tier Migration Summary\n\n")
        f.write(f"Total patterns: {total_stats['total']}\n")
        f.write(f"Patterns migrated: {total_stats['migrated']}\n\n")
        f.write("## New Tier Distribution\n\n")
        f.write(f"- **Public (Free/Demo)**: {total_stats['public']} patterns\n")
        f.write(f"- **AI (Professional)**: {total_stats['ai']} patterns\n")
        f.write(f"- **Enterprise**: {total_stats['enterprise']} patterns\n")
    
    print(f"\n📄 Summary saved to: {summary_path}")

if __name__ == "__main__":
    main()