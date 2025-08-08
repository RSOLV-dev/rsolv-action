# Archive Guidelines for RSOLV Landing Page

This document outlines standardized procedures for archiving code, documentation, and data files in the RSOLV Landing Page project.

## Archive Directories Structure

The project maintains standardized archive directories at the following locations:

1. **Documentation Archives**: `/docs/archive/`
   - For outdated or deprecated documentation files
   - Files should retain their original extension (e.g., .md) 

2. **Data Archives**: `/priv/static/data/archive/`
   - For sample, test, or historical data files
   - Files should be organized in subdirectories matching their original location

3. **Code Archives**: Not currently implemented
   - Future consideration: `/lib/archive/` for keeping historical implementations

## When to Archive

Items should be moved to the appropriate archive directory when:

1. A document or code file is replaced by a newer version but contains historical information worth preserving
2. Example or sample data is no longer used in current implementations but may be needed for reference
3. Feature implementations are replaced but may need to be referenced in the future
4. Configuration templates or examples are outdated but still provide useful reference

## Archive Naming Conventions

- **Documentation**: Retain original filename 
- **Data Files**: Use the convention `YYYYMMDD_original_filename.ext`
- **Test/Sample Data**: Use `sample_` or `example_` prefix, not `old_`

## Backup Files (.bak)

Backup files are different from archived files:

1. **Temporary Backups** (.bak files):
   - Generated automatically during processing operations
   - Naming convention: `original_filename.YYYYMMDDHHMMSS.bak`
   - Should be automatically cleaned up after 30 days
   - Located in the same directory as the original files

2. **Archived Files**:
   - Manually moved to specific archive directories
   - Retained indefinitely or until explicitly removed
   - Properly documented in this archive guide

## Queue Backup File Management

The system creates backup files in `/priv/static/data/tagging_queue/` during queue processing. To prevent excessive accumulation:

1. A cleanup script runs weekly to remove backup files older than 30 days
2. Only one backup per day is preserved after 7 days
3. Files are not moved to the archive directory but simply deleted when they expire

## Documentation Standards

When documenting archived materials:

1. Update the main documentation to reference the archived version when relevant
2. Avoid phrases like "old" or "deprecated" in favor of specific version or date information
3. Include a note about why the material was archived and what replaced it

## Code Deprecation Standards

When deprecated code must remain in the codebase temporarily:

1. Add `@deprecated "Reason for deprecation. Use X instead. Will be removed on YYYY-MM-DD"` doc attribute
2. Log a warning when deprecated functions are called
3. Create a GitHub issue to track the removal of deprecated code

## Archive Review Process

The archive directories should be reviewed quarterly to:

1. Ensure all archived materials still provide value
2. Remove items that are no longer relevant
3. Update this documentation with any new archiving patterns or requirements

---

*Last Updated: May 6, 2025*