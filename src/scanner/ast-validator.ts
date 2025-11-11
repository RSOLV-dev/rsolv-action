import { RsolvApiClient } from '../external/api-client.js';
import { logger } from '../utils/logger.js';
import type { Vulnerability } from '../security/types.js';
import * as crypto from 'crypto';

/**
 * Result from AST validation for a single vulnerability
 * @example
 * ```typescript
 * const result: ValidationResult = {
 *   vulnerability: originalVuln,
 *   isValid: true,
 *   confidence: 0.95,
 *   reason: undefined
 * };
 * ```
 */
export interface ValidationResult {
  vulnerability: Vulnerability;
  isValid: boolean;
  confidence: number;
  reason?: string;
}

interface ValidationResponse {
  validated: Array<{
    id: string;
    isValid: boolean;
    confidence: number;
    reason?: string;
    astContext?: {
      inUserInputFlow: boolean;
      hasValidation: boolean;
    };
  }>;
  stats: {
    total: number;
    validated: number;
    rejected: number;
  };
}

/**
 * ASTValidator service for server-side vulnerability validation
 * 
 * This service sends detected vulnerabilities to RSOLV-api for
 * AST-based validation to reduce false positives.
 * 
 * @example
 * ```typescript
 * const validator = new ASTValidator(apiKey);
 * const validated = await validator.validateVulnerabilities(
 *   vulnerabilities,
 *   fileContents
 * );
 * console.log(`Filtered ${vulnerabilities.length - validated.length} false positives`);
 * ```
 */
export class ASTValidator {
  private apiClient: RsolvApiClient;
  private cache: Map<string, ValidationResult> = new Map();
  
  constructor(apiKey: string) {
    this.apiClient = new RsolvApiClient({
      apiKey,
      baseUrl: process.env.RSOLV_API_URL || 'https://api.rsolv.dev'
    });
  }
  
  /**
   * Validate vulnerabilities using server-side AST analysis
   * 
   * @param vulnerabilities - Array of detected vulnerabilities
   * @param fileContents - Map of file paths to their contents
   * @returns Array of validated vulnerabilities (false positives removed)
   * 
   * @example
   * ```typescript
   * const fileContents = new Map([
   *   ['app.js', 'eval(userInput); // dangerous!']
   * ]);
   * const validated = await validator.validateVulnerabilities(vulns, fileContents);
   * // Returns only real vulnerabilities, filtering out false positives
   * ```
   */
  async validateVulnerabilities(
    vulnerabilities: Vulnerability[],
    fileContents: Map<string, string>
  ): Promise<Vulnerability[]> {
    if (vulnerabilities.length === 0) {
      return [];
    }

    logger.info(`Validating ${vulnerabilities.length} vulnerabilities with AST analysis`);

    // Batch vulnerabilities to avoid overwhelming the API with massive payloads
    // Large codebases can generate hundreds of vulnerabilities across hundreds of files
    // Sending all file contents at once can result in multi-megabyte requests that hang
    const BATCH_SIZE = 50; // Process 50 vulnerabilities at a time
    const batches: Vulnerability[][] = [];

    for (let i = 0; i < vulnerabilities.length; i += BATCH_SIZE) {
      batches.push(vulnerabilities.slice(i, i + BATCH_SIZE));
    }

    logger.info(`Batching ${vulnerabilities.length} vulnerabilities into ${batches.length} batches of up to ${BATCH_SIZE}`);

    const validatedResults: Vulnerability[] = [];

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      logger.info(`Validating batch ${i + 1}/${batches.length} (${batch.length} vulnerabilities)`);

      try {
        // Only send file contents for files referenced in this batch
        const batchFileContents = this.getRelevantFileContents(batch, fileContents);

        // Prepare request data for this batch
        const request = this.prepareValidationRequest(batch, batchFileContents);

        // Call validation API for this batch
        const response = await this.callValidationAPI(request);

        // Process response and collect validated vulnerabilities
        const batchValidated = this.processValidationResponse(batch, response);
        validatedResults.push(...batchValidated);

        logger.info(`Batch ${i + 1}/${batches.length} validated: ${batchValidated.length}/${batch.length} confirmed`);
      } catch (error) {
        logger.warn(`Batch ${i + 1}/${batches.length} validation failed, including all ${batch.length} vulnerabilities`, {
          error: error instanceof Error ? error.message : error
        });
        // Fail open for this batch - include all vulnerabilities from failed batch
        validatedResults.push(...batch);
      }
    }

    logger.info(`AST validation complete: ${validatedResults.length}/${vulnerabilities.length} vulnerabilities validated`);
    return validatedResults;
  }

  /**
   * Extract only the file contents needed for a batch of vulnerabilities
   * This dramatically reduces payload size for large codebases
   */
  private getRelevantFileContents(
    vulnerabilities: Vulnerability[],
    allFileContents: Map<string, string>
  ): Map<string, string> {
    const relevantFiles = new Set<string>();

    // Collect unique file paths from this batch
    for (const vuln of vulnerabilities) {
      if (vuln.filePath) {
        relevantFiles.add(vuln.filePath);
      }
    }

    // Build map with only relevant files
    const relevantContents = new Map<string, string>();
    for (const filePath of relevantFiles) {
      const content = allFileContents.get(filePath);
      if (content !== undefined) {
        relevantContents.set(filePath, content);
      }
    }

    return relevantContents;
  }
  
  private prepareValidationRequest(
    vulnerabilities: Vulnerability[],
    fileContents: Map<string, string>
  ) {
    // Convert vulnerabilities to API format
    const vulnsForApi = vulnerabilities.map(v => ({
      id: `${v.type}-${v.line}-${v.column || 0}`, // Generate ID from available fields
      type: v.type, // Include type field for API
      patternId: v.type, // Use type as pattern ID
      file: v.filePath || '', // API expects 'file', not 'filePath'
      line: v.line,
      code: v.snippet || '', // Use snippet as code
      severity: v.severity
    }));

    // Build files object from map with proper structure
    const files: Record<string, { content: string }> = {};
    for (const [path, content] of fileContents) {
      files[path] = { content };
    }

    return {
      vulnerabilities: vulnsForApi,
      files
    };
  }
  
  private async callValidationAPI(request: any): Promise<ValidationResponse> {
    const response = await this.apiClient.validateVulnerabilities(request);
    if (process.env.DEBUG_AST_VALIDATION) {
      console.log('AST Validation Request:', JSON.stringify(request, null, 2));
      console.log('AST Validation Response:', JSON.stringify(response, null, 2));
    }
    return response;
  }
  
  private processValidationResponse(
    vulnerabilities: Vulnerability[],
    response: ValidationResponse
  ): Vulnerability[] {
    // Create a map for quick lookup
    const validationMap = new Map(
      response.validated.map(v => [v.id, v])
    );
    
    // Filter vulnerabilities based on validation results
    const validated = vulnerabilities.filter(vuln => {
      const vulnId = `${vuln.type}-${vuln.line}-${vuln.column || 0}`;
      const validation = validationMap.get(vulnId);
      
      if (!validation) {
        // No validation result, keep the vulnerability
        return true;
      }
      
      if (!validation.isValid) {
        logger.debug(`Filtered false positive: ${vuln.filePath}:${vuln.line} - ${validation.reason}`);
        return false;
      }
      
      return true;
    });
    
    logger.info(`AST validation complete: ${response.stats.rejected} false positives filtered out`);
    return validated;
  }
  
  /**
   * Generate a cache key for a vulnerability
   * Used internally for caching validation results
   */
  private getCacheKey(filePath: string, patternId: string, fileHash: string): string {
    return `${filePath}:${patternId}:${fileHash}`;
  }
}