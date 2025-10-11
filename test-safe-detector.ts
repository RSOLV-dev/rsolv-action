import { SafeDetector } from './src/security/safe-detector.js';

async function testSafeDetector() {
  console.log("=== Testing SafeDetector with real hang scenario ===\n");
  
  const detector = new SafeDetector();
  
  // The actual user.rb content that caused the hang
  const userRbContent = `# frozen_string_literal: true
require "encryption"

class User < ApplicationRecord
  validates :password, presence: true,
                       confirmation: true,
                       length: {within: 6..40},
                       on: :create,
                       if: :password

  validates_presence_of :email
  validates_uniqueness_of :email
  validates_format_of :email, with: /.+@.+\..+/i

  has_one :retirement, dependent: :destroy
  has_one :paid_time_off, dependent: :destroy
  has_one :work_info, dependent: :destroy
  has_many :performance, dependent: :destroy
  has_many :pay, dependent: :destroy
  has_many :messages, foreign_key: :receiver_id, dependent: :destroy

  before_save :hash_password
  after_create { generate_token(:auth_token) }
  before_create :build_benefits_data

  def build_benefits_data
    build_retirement(POPULATE_RETIREMENTS.sample)
    build_paid_time_off(POPULATE_PAID_TIME_OFF.sample).schedule.build(POPULATE_SCHEDULE.sample)
    build_work_info(POPULATE_WORK_INFO.sample)
    performance.build(POPULATE_PERFORMANCE.sample)
  end

  def full_name
    "#{self.first_name} #{self.last_name}"
  end

  private

  def self.authenticate(email, password)
    auth = nil
    user = find_by_email(email)
    raise "#{email} doesn't exist!" if !(user)
    if user.password == Digest::MD5.hexdigest(password)
      auth = user
    else
      raise "Incorrect Password!"
    end
    return auth
  end

  def hash_password
    if will_save_change_to_password?
      self.password = Digest::MD5.hexdigest(self.password)
    end
  end

  def generate_token(column)
    loop do
      self[column] = Encryption.encrypt_sensitive_value(self.id)
      break unless User.exists?(column => self[column])
    end

    self.save!
  end
end`;

  console.log("Testing with user.rb content (1878 bytes)...\n");
  
  const start = Date.now();
  const vulnerabilities = await detector.detect(userRbContent, 'ruby', 'app/models/user.rb');
  const duration = Date.now() - start;
  
  console.log(`✅ Scan completed in ${duration}ms`);
  console.log(`Found ${vulnerabilities.length} vulnerabilities`);
  console.log(`Skipped patterns: ${detector.getSkippedPatterns().join(', ') || 'none'}`);
  
  if (vulnerabilities.length > 0) {
    console.log("\nVulnerabilities found:");
    vulnerabilities.forEach(v => {
      console.log(`  - Line ${v.line}: ${v.type} (${v.severity})`);
    });
  }
  
  // Test with a known problematic pattern
  console.log("\n\nTesting with catastrophic backtracking pattern...");
  const problematicCode = 'a'.repeat(100) + 'X';
  const start2 = Date.now();
  const result2 = await detector.detect(problematicCode, 'javascript');
  const duration2 = Date.now() - start2;
  
  console.log(`✅ Handled problematic pattern in ${duration2}ms`);
  
  detector.cleanup();
  console.log("\n=== Test Complete ===");
}

testSafeDetector().catch(console.error);
