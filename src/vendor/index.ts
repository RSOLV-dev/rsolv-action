/**
 * RFC-047: Vendor Library Detection - Main Export
 */

export * from './types';
export { VendorDetector } from './vendor-detector';
export { DependencyAnalyzer } from './dependency-analyzer';
export { VendorVulnerabilityHandler } from './vulnerability-handler';
export { UpdateRecommender } from './update-recommender';
export { VendorIssueCreator } from './issue-creator';

import { 
  VendorDetector,
  DependencyAnalyzer,
  VendorVulnerabilityHandler,
  UpdateRecommender,
  VendorIssueCreator,
  Vulnerability,
  VendorVulnerability
} from './index';

/**
 * Main integration class for vendor library detection
 */
export class VendorDetectionIntegration {
  private detector: VendorDetector;
  private analyzer: DependencyAnalyzer;
  private handler: VendorVulnerabilityHandler;
  private recommender: UpdateRecommender;
  private issueCreator: VendorIssueCreator;
  
  constructor() {
    this.detector = new VendorDetector();
    this.analyzer = new DependencyAnalyzer();
    this.handler = new VendorVulnerabilityHandler(this.detector, this.analyzer);
    this.recommender = new UpdateRecommender();
    this.issueCreator = new VendorIssueCreator();
  }
  
  /**
   * Check if a file is vendor code
   */
  async isVendorFile(filePath: string): Promise<boolean> {
    return this.detector.isVendorFile(filePath);
  }
  
  /**
   * Process a vulnerability and determine handling strategy
   */
  async processVulnerability(vulnerability: Vulnerability): Promise<any> {
    console.log(`[VendorDetection] Processing ${vulnerability.type} in ${vulnerability.file}`);
    
    // Get the handling report
    const report = await this.handler.handle(vulnerability);
    console.log(`[VendorDetection] Type: ${report.type}, Action: ${report.action}`);
    
    // If it's vendor code, create appropriate issue
    if (report.type === 'vendor' && report.action === 'update') {
      const library = report.library || await this.detector.identifyLibrary(vulnerability.file);
      
      if (library) {
        // Get update recommendations
        const recommendation = await this.recommender.recommendUpdate(library, vulnerability);
        
        // Create vendor-specific issue
        const vendorVuln: VendorVulnerability = {
          ...vulnerability,
          library,
          recommendedVersion: recommendation.minimumSafeVersion,
          updateCommand: recommendation.updateStrategies[0]?.command
        };
        
        const issue = await this.issueCreator.createIssue(vendorVuln);
        
        return {
          type: 'vendor',
          action: 'issue_created',
          issue,
          recommendation,
          library,
          shouldNotPatch: true
        };
      }
    }
    
    // Application code - proceed with normal fix
    return {
      type: 'application',
      action: 'fix',
      shouldPatch: true
    };
  }
  
  /**
   * Check if vulnerability should be fixed or updated
   */
  async shouldPatchFile(filePath: string): Promise<boolean> {
    const isVendor = await this.isVendorFile(filePath);
    return !isVendor; // Only patch non-vendor files
  }
}