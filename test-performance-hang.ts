import { SecurityDetectorV2 } from './src/security/detector-v2.js';

async function testPerformanceHang() {
  const performanceRb = `# frozen_string_literal: true
class Performance < ApplicationRecord
  belongs_to :user

  def reviewer_name
   u = User.find_by_id(self.reviewer)
   u.full_name if u.respond_to?("fullname")
  end
end
`;

  console.log("Testing performance.rb for hang...");
  const detector = new SecurityDetectorV2();
  
  const start = Date.now();
  const timeout = setTimeout(() => {
    console.error("❌ HANG DETECTED - Scan took > 5 seconds");
    process.exit(1);
  }, 5000);
  
  try {
    const vulns = await detector.detect(performanceRb, 'ruby', 'app/models/performance.rb');
    clearTimeout(timeout);
    const duration = Date.now() - start;
    console.log(`✅ Scan completed in ${duration}ms`);
    console.log(`Found ${vulns.length} vulnerabilities`);
  } catch (error) {
    clearTimeout(timeout);
    console.error("Error:", error);
    process.exit(1);
  }
}

testPerformanceHang();
