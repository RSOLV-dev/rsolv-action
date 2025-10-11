import { SecurityDetectorV2 } from './src/security/detector-v2.js';
import * as fs from 'fs';
import * as path from 'path';

async function testCumulativeScan() {
  const railsgoatPath = '/tmp/railsgoat-inspect';
  
  const files = [
    'app/models/paid_time_off.rb',
    'app/models/pay.rb',
    'app/models/performance.rb',
    'app/models/retirement.rb',
    'app/models/schedule.rb',
    'app/models/user.rb',
    'app/models/work_info.rb',
    'config/application.rb'
  ];
  
  console.log("=== Testing Cumulative Scan Around File 70-71 ===\n");
  
  const detector = new SecurityDetectorV2();
  
  for (let i = 0; i < files.length; i++) {
    const filePath = files[i];
    const fullPath = path.join(railsgoatPath, filePath);
    
    if (!fs.existsSync(fullPath)) {
      console.log(`File skipped: ${filePath} - NOT FOUND`);
      continue;
    }
    
    const content = fs.readFileSync(fullPath, 'utf-8');
    const fileNum = i + 68;
    
    console.log(`\nFile ${fileNum}: ${filePath} (${content.length} bytes)`);
    
    const start = Date.now();
    const timeout = setTimeout(() => {
      console.log(`\n❌ TIMEOUT on file ${fileNum}: ${filePath}`);
      process.exit(1);
    }, 5000);
    
    try {
      const vulns = await detector.detect(content, 'ruby', filePath);
      clearTimeout(timeout);
      const duration = Date.now() - start;
      
      if (duration > 1000) {
        console.log(`  ⚠️  SLOW - ${duration}ms (${vulns.length} vulnerabilities)`);
      } else if (duration > 100) {
        console.log(`  ⚡ ${duration}ms (${vulns.length} vulnerabilities)`);
      } else {
        console.log(`  ✅ ${duration}ms (${vulns.length} vulnerabilities)`);
      }
    } catch (error) {
      clearTimeout(timeout);
      console.log(`  ❌ ERROR: ${error.message}`);
    }
  }
  
  console.log("\n=== Cumulative Scan Complete - No Hang! ===");
}

testCumulativeScan();
