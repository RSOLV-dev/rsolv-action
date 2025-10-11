import { RepositoryScanner } from './src/scanner/repository-scanner.js';
import type { ScanConfig } from './src/scanner/types.js';

async function testTimeoutFix() {
  console.log("=== Testing Timeout Fix on railsgoat Files ===\n");

  const scanner = new RepositoryScanner();

  const config: ScanConfig = {
    repository: {
      owner: 'RSOLV-dev',
      name: 'railsgoat',
      defaultBranch: 'master'
    },
    enableASTValidation: false,
    createIssues: false,
    issueLabel: 'security'
  };

  console.log("Starting scan with 30-second per-file timeout...\n");

  const start = Date.now();
  try {
    const result = await scanner.scan(config);
    const duration = (Date.now() - start) / 1000;

    console.log("\n=== Scan Complete! ===");
    console.log("Total time: " + duration.toFixed(1) + " seconds");
    console.log("Files scanned: " + result.scannedFiles + "/" + result.totalFiles);
    console.log("Vulnerabilities found: " + result.vulnerabilities.length);
  } catch (error) {
    console.error("\nScan failed:", error.message);
    process.exit(1);
  }
}

testTimeoutFix();
