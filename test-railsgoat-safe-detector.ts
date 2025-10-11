import { RepositoryScanner } from './src/scanner/repository-scanner.js';
import type { ScanConfig } from './src/scanner/types.js';

async function testRailsgoatWithSafeDetector() {
  console.log("=== Testing SafeDetector on RailsGoat Repository ===\n");

  const scanner = new RepositoryScanner();

  const config: ScanConfig = {
    repository: {
      owner: 'RSOLV-dev',
      name: 'railsgoat',
      defaultBranch: 'master'
    },
    enableASTValidation: false, // Disable to speed up test
    createIssues: false,
    issueLabel: 'security'
  };

  console.log("Starting scan with SafeDetector (worker thread protection)...\n");

  const start = Date.now();
  try {
    const result = await scanner.scan(config);
    const duration = (Date.now() - start) / 1000;

    console.log("\n=== ✅ SCAN COMPLETED SUCCESSFULLY! ===");
    console.log(`Total time: ${duration.toFixed(1)} seconds`);
    console.log(`Files scanned: ${result.scannedFiles}/${result.totalFiles}`);
    console.log(`Vulnerabilities found: ${result.vulnerabilities.length}`);

    console.log("\nGrouped vulnerabilities:");
    result.groupedVulnerabilities.forEach(group => {
      console.log(`  - ${group.type} (${group.severity}): ${group.count} issues in ${group.files.length} files`);
    });

    // Check if we found vulnerabilities in user.rb (the problematic file)
    const userRbVulns = result.vulnerabilities.filter(v => v.filePath?.includes('user.rb'));
    if (userRbVulns.length > 0) {
      console.log(`\n✅ Found ${userRbVulns.length} vulnerabilities in user.rb (the file that was causing hangs)`);
    }

    console.log("\n=== SUCCESS: SafeDetector prevented hangs and completed the scan! ===");

  } catch (error: any) {
    const duration = (Date.now() - start) / 1000;
    console.error(`\n❌ Scan failed after ${duration.toFixed(1)} seconds:`, error.message);
    process.exit(1);
  }
}

testRailsgoatWithSafeDetector().catch(console.error);