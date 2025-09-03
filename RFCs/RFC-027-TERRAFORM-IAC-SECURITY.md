# RFC-027: Terraform/IaC Security Test Generation

**Status**: Draft  
**Created**: 2025-06-24  
**Author**: RSOLV Team

## Summary

Extend RSOLV's security analysis and test generation capabilities to Infrastructure as Code (IaC), with initial focus on Terraform. This includes detecting security misconfigurations, generating policy-as-code tests, and validating infrastructure changes don't introduce vulnerabilities.

## Problem Statement

Infrastructure as Code has become critical to modern DevOps, but it introduces unique security challenges:

1. **Misconfiguration Risks**: IaC misconfigurations are a leading cause of cloud breaches
2. **Different Vulnerability Types**: IaC vulnerabilities differ from application code (e.g., open S3 buckets vs SQL injection)
3. **Policy Violations**: Need to enforce organizational security policies
4. **Compliance Requirements**: Many organizations need to prove infrastructure compliance
5. **Test Paradigm Difference**: IaC tests validate configuration, not behavior

Current RSOLV focuses on application code vulnerabilities. We need specialized handling for IaC security.

## Proposed Solution

### 1. IaC-Specific Vulnerability Types

Extend our vulnerability taxonomy for IaC:

```typescript
enum IaCVulnerabilityType {
  // Storage
  PUBLIC_S3_BUCKET = 'public-s3-bucket',
  UNENCRYPTED_STORAGE = 'unencrypted-storage',
  MISSING_VERSIONING = 'missing-versioning',
  
  // Network
  OPEN_SECURITY_GROUP = 'open-security-group',
  PUBLIC_RDS = 'public-rds',
  MISSING_TLS = 'missing-tls',
  
  // Access Control
  OVERLY_PERMISSIVE_IAM = 'overly-permissive-iam',
  HARDCODED_CREDENTIALS = 'hardcoded-credentials',
  MISSING_MFA = 'missing-mfa',
  
  // Compliance
  MISSING_TAGS = 'missing-tags',
  NON_COMPLIANT_ENCRYPTION = 'non-compliant-encryption',
  AUDIT_LOGGING_DISABLED = 'audit-logging-disabled'
}
```

### 2. IaC Pattern Detection

Terraform-specific patterns:

```typescript
interface TerraformPattern extends SecurityPattern {
  resourceTypes: string[]; // e.g., ['aws_s3_bucket', 'azurerm_storage_account']
  providers: string[]; // e.g., ['aws', 'azurerm', 'google']
  policyRules?: PolicyRule[]; // OPA/Sentinel rules
  terraformVersion?: string; // Version constraints
}

// Example pattern
const publicS3BucketPattern: TerraformPattern = {
  id: 'terraform-public-s3',
  name: 'Public S3 Bucket',
  type: IaCVulnerabilityType.PUBLIC_S3_BUCKET,
  severity: 'critical',
  resourceTypes: ['aws_s3_bucket'],
  providers: ['aws'],
  patterns: {
    hcl: [
      // HCL-specific patterns
      /acl\s*=\s*["']public-read["']/,
      /acl\s*=\s*["']public-read-write["']/
    ]
  },
  policyRules: [{
    engine: 'opa',
    rule: 'deny[msg] { input.acl == "public-read" }'
  }]
};
```

### 3. Policy-as-Code Test Generation

Generate tests using popular IaC testing frameworks:

#### Terratest (Go)
```go
func TestS3BucketIsPrivate(t *testing.T) {
    terraformOptions := &terraform.Options{
        TerraformDir: "../terraform",
    }
    
    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)
    
    bucketID := terraform.Output(t, terraformOptions, "bucket_id")
    aws.AssertS3BucketPolicyDoesNotAllowPublicAccess(t, awsRegion, bucketID)
}
```

#### Kitchen-Terraform (Ruby)
```ruby
control 's3-bucket-private' do
  title 'S3 bucket should not be publicly accessible'
  desc 'Verify S3 bucket ACL and policies prevent public access'
  
  describe aws_s3_bucket(bucket_name) do
    it { should_not be_public }
    its('acl.grants') { should_not include 'AllUsers' }
  end
end
```

#### Terraform Compliance (Python)
```gherkin
Feature: S3 Bucket Security
  Scenario: S3 buckets must not be publicly readable
    Given I have aws_s3_bucket defined
    Then it must not have acl property with value public-read
    And it must have versioning enabled
    And it must have encryption enabled
```

### 4. Test Framework Detection for IaC

Extend TestFrameworkDetector:

```typescript
class IaCTestFrameworkDetector extends TestFrameworkDetector {
  private iacFrameworks = {
    terratest: {
      files: ['go.mod'],
      patterns: [/github.com\/gruntwork-io\/terratest/],
      testPattern: '*_test.go'
    },
    'kitchen-terraform': {
      files: ['.kitchen.yml', 'Gemfile'],
      patterns: [/kitchen-terraform/],
      testPattern: 'test/integration/**/*_spec.rb'
    },
    'terraform-compliance': {
      files: ['requirements.txt', 'features/'],
      patterns: [/terraform-compliance/],
      testPattern: 'features/*.feature'
    },
    sentinel: {
      files: ['sentinel.hcl'],
      patterns: [/policy\s+".+"/],
      testPattern: 'policies/*.sentinel'
    }
  };
  
  detectIaCFramework(repoStructure: Record<string, string>): IaCFramework {
    // Detection logic
  }
}
```

### 5. Fix Generation for IaC

IaC fixes are configuration changes:

```typescript
class IaCFixGenerator {
  generateFix(vulnerability: IaCVulnerability): IaCFix {
    switch (vulnerability.type) {
      case IaCVulnerabilityType.PUBLIC_S3_BUCKET:
        return {
          description: 'Make S3 bucket private',
          changes: [{
            file: vulnerability.file,
            from: 'acl = "public-read"',
            to: 'acl = "private"'
          }],
          additionalResources: [
            this.generateBucketPolicy(),
            this.generateAccessLogging()
          ]
        };
    }
  }
  
  private generateBucketPolicy(): string {
    return `
resource "aws_s3_bucket_policy" "secure_policy" {
  bucket = aws_s3_bucket.main.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "\${aws_s3_bucket.main.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      }
    ]
  })
}`;
  }
}
```

### 6. Integration with Existing Architecture

```typescript
// Extend SecurityAnalyzer
class IaCSecurityAnalyzer extends SecurityAnalyzer {
  async analyze(files: Map<string, string>): Promise<IaCAnalysisResult> {
    const terraformFiles = this.filterTerraformFiles(files);
    const patterns = await this.patternSource.getIaCPatterns();
    
    // HCL parsing for better accuracy
    const hclAST = await this.parseHCL(terraformFiles);
    
    // Apply patterns
    const findings = this.detectVulnerabilities(hclAST, patterns);
    
    // Generate fixes and tests
    const fixes = this.generateFixes(findings);
    const tests = this.generateTests(findings);
    
    return { findings, fixes, tests };
  }
}
```

## Implementation Plan

### Phase 1: Core IaC Support (1 week)
1. Define IaC vulnerability types
2. Create Terraform pattern structure
3. Implement HCL parsing (using @cdktf/hcl2json)
4. Add IaC pattern detection

### Phase 2: Pattern Library (2 weeks)
1. AWS security patterns (S3, IAM, VPC, RDS)
2. Azure security patterns
3. GCP security patterns
4. Cross-cloud patterns (encryption, access control)

### Phase 3: Test Generation (1 week)
1. Terratest template generation
2. Kitchen-Terraform support
3. Terraform Compliance BDD tests
4. Policy-as-code generation

### Phase 4: Fix Generation (1 week)
1. Configuration fix templates
2. Resource addition for compliance
3. Module recommendations
4. Multi-file fixes (e.g., adding variables.tf)

### Phase 5: Validation (1 week)
1. Test with terragoat (vulnerable Terraform)
2. Validate with real-world Terraform repos
3. Performance testing with large configurations
4. Integration testing with CI/CD pipelines

## Success Metrics

1. **Detection Rate**: >90% of OWASP Top 10 for Cloud
2. **Test Coverage**: Generate tests for 100% of detected issues
3. **Fix Accuracy**: 95% of generated fixes should pass validation
4. **Performance**: Analyze 1000 Terraform files in <30 seconds
5. **Framework Support**: Cover 80% of Terraform testing frameworks

## Example Patterns

### 1. Public S3 Bucket
```hcl
# Vulnerable
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"  # VULNERABILITY
}

# Fixed
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### 2. Open Security Group
```hcl
# Vulnerable
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABILITY
  }
}

# Fixed
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]  # Restricted to admin CIDR
  }
}
```

## Challenges & Mitigations

### 1. Dynamic Values
- **Challenge**: Terraform uses variables and expressions
- **Mitigation**: Trace variable definitions and evaluate simple expressions

### 2. Modules
- **Challenge**: Security issues can be in remote modules
- **Mitigation**: Analyze module sources when possible, flag unknowns

### 3. Provider Differences
- **Challenge**: Each cloud provider has different resources
- **Mitigation**: Provider-specific pattern sets with common abstractions

### 4. State Files
- **Challenge**: State files contain sensitive data
- **Mitigation**: Never analyze state files, only configuration

## Alternatives Considered

1. **Checkov Integration**: Use existing tool vs building our own
   - Decided to build for better integration with RSOLV ecosystem

2. **Static Only**: No runtime validation
   - Decided to generate tests for runtime validation

3. **Single Cloud**: Start with AWS only
   - Decided to support multi-cloud from start

## Future Extensions

1. **Kubernetes/Helm Support**: Extend to K8s manifests
2. **CloudFormation/ARM**: Other IaC formats
3. **Cost Optimization**: Security + cost recommendations
4. **Drift Detection**: Compare config to actual state
5. **Remediation Tracking**: Track infrastructure fixes

## Phase 6D Validation Insights

From our Phase 6D validation (2025-06-24), we learned:

### Test Framework Detection
1. **Terratest (Go)**: Popular but requires Go AST parsing support
   - Uses `github.com/gruntwork-io/terratest` import
   - Test files typically in `test/` directory with `_test.go` suffix
   - Would need Go parser integration per RFC-021

2. **Kitchen-Terraform (Ruby)**: Ruby-based testing framework
   - Configured via `.kitchen.yml` file
   - Uses RSpec/Serverspec for assertions
   - Could leverage existing Ruby test generation

3. **Terraform Compliance (BDD)**: Uses Gherkin syntax
   - Feature files define compliance rules
   - Could generate `.feature` files for policy tests
   - Example: "Given I have aws_s3_bucket defined, Then it must not have acl property with value public-read"

### Pattern Requirements
1. **HCL Parser Needed**: Terraform uses HCL (HashiCorp Configuration Language)
   - Not compatible with existing JavaScript/TypeScript parsers
   - Would benefit from Elixir AST service (RFC-023) for proper parsing

2. **Resource-Aware Patterns**: IaC patterns must understand resource types
   - `aws_s3_bucket` → check for `acl`, `versioning`, `server_side_encryption_configuration`
   - `aws_security_group` → check for `0.0.0.0/0` in `cidr_blocks`
   - `aws_db_instance` → check for `publicly_accessible`, `storage_encrypted`

3. **Cross-Reference Analysis**: Many IaC vulnerabilities require understanding relationships
   - S3 bucket ACL + bucket policy + public access block
   - Security group rules + network ACLs + route tables

### Implementation Notes
- Current system generates generic tests for `.tf` files
- Without IaC-specific patterns, only catches general issues (hardcoded secrets)
- Test generation works but produces JavaScript-style tests, not IaC test frameworks
- Could reuse existing pattern architecture with IaC-specific vulnerability types

## Security Considerations

1. **Sensitive Variables**: Never log or expose sensitive values
2. **State File Security**: Warn about state file exposure
3. **Module Security**: Validate module sources
4. **Provider Credentials**: Ensure no credentials in code

## References

- [OWASP Top 10 for Cloud](https://owasp.org/www-project-cloud-top-10/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Terraform Security Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [Terragoat - Vulnerable Terraform](https://github.com/bridgecrewio/terragoat)
- [Checkov Patterns](https://www.checkov.io/5.Policy%20Index/terraform.html)