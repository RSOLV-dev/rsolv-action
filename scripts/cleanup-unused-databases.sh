#!/bin/bash
# Database Cleanup Script
# Documents and optionally removes unused databases after RFC-037 consolidation

echo "Database Status Documentation"
echo "================================"
echo ""
echo "After RFC-037 consolidation (Service Consolidation), the database structure is:"
echo ""
echo "ACTIVE DATABASES:"
echo "- rsolv_landing_prod: Production database (contains all web + API data)"
echo "- rsolv_staging: Staging database"
echo ""
echo "UNUSED DATABASES (can be removed):"
echo "- rsolv_api_prod: Empty, replaced by consolidated rsolv_landing_prod"
echo "- rsolv_platform_prod: Empty, never used (created by mistake)"
echo ""

if [ "$1" == "--execute" ]; then
    echo "⚠️  WARNING: This will DROP the unused databases!"
    read -p "Are you sure you want to remove rsolv_api_prod and rsolv_platform_prod? (yes/no): " confirm
    
    if [ "$confirm" == "yes" ]; then
        echo "Removing unused databases..."
        
        # Drop rsolv_api_prod
        kubectl exec postgres-nfs-65f6bd597-r4gft -- psql -U rsolv -h localhost -d postgres -c "DROP DATABASE IF EXISTS rsolv_api_prod;" 2>&1
        echo "✅ Dropped rsolv_api_prod"
        
        # Drop rsolv_platform_prod  
        kubectl exec postgres-nfs-65f6bd597-r4gft -- psql -U rsolv -h localhost -d postgres -c "DROP DATABASE IF EXISTS rsolv_platform_prod;" 2>&1
        echo "✅ Dropped rsolv_platform_prod"
        
        echo ""
        echo "Cleanup complete! Current databases:"
        kubectl exec postgres-nfs-65f6bd597-r4gft -- psql -U rsolv -h localhost -d postgres -c "\l" 2>&1 | grep rsolv
    else
        echo "Cleanup cancelled."
    fi
else
    echo "To remove the unused databases, run:"
    echo "  ./scripts/cleanup-unused-databases.sh --execute"
    echo ""
    echo "Current database list:"
    kubectl exec postgres-nfs-65f6bd597-r4gft -- psql -U rsolv -h localhost -d postgres -c "\l" 2>&1 | grep rsolv
fi