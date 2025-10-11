import { createPatternSource } from './src/security/pattern-source.js';

async function testUserRb() {
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
    # Uncomment below line to use encrypted SSN(s)
    #work_info.build_key_management(:iv => SecureRandom.hex(32))
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
end
`;

  console.log("=== Testing user.rb Against Each Pattern ===\n");
  
  const patternSource = createPatternSource();
  const patterns = await patternSource.getPatternsByLanguage('ruby');
  
  for (let i = 0; i < patterns.length; i++) {
    const pattern = patterns[i];
    console.log(`Pattern ${i + 1}/${patterns.length}: ${pattern.id}`);
    
    if (pattern.patterns?.regex) {
      for (let j = 0; j < pattern.patterns.regex.length; j++) {
        const regex = pattern.patterns.regex[j];
        const regexStr = regex.source.substring(0, 80) + (regex.source.length > 80 ? '...' : '');
        console.log(`  Regex ${j + 1}: ${regexStr}`);
        
        const start = Date.now();
        const timeout = setTimeout(() => {
          console.log(`\n❌❌❌ HANG FOUND! ❌❌❌`);
          console.log(`Pattern: ${pattern.id}`);
          console.log(`Regex ${j + 1}: ${regex.source}`);
          console.log(`Flags: ${regex.flags}`);
          process.exit(0);
        }, 2000);
        
        try {
          regex.lastIndex = 0;
          let matchCount = 0;
          let match;
          
          while ((match = regex.exec(userRbContent)) !== null) {
            matchCount++;
            if (!regex.global || matchCount > 1000) break;
          }
          
          clearTimeout(timeout);
          const duration = Date.now() - start;
          
          if (duration > 100) {
            console.log(`    ⚠️ ${duration}ms, ${matchCount} matches`);
          } else {
            console.log(`    ✅ ${duration}ms, ${matchCount} matches`);
          }
        } catch (error) {
          clearTimeout(timeout);
          console.log(`    ❌ ERROR: ${error.message}`);
        }
      }
    }
    console.log();
  }
  
  console.log("=== All Patterns Tested Successfully ===");
}

testUserRb();
