import { IssueContext, ActionConfig, AnalysisData, IssueType } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { getAiClient } from './client.js';
import { buildAnalysisPrompt } from './prompts.js';

/**
 * Analyze an issue with AI to determine the best approach for fixing it
 */
export async function analyzeIssue(
  issue: IssueContext,
  config: ActionConfig
): Promise<AnalysisData> {
  logger.info(`Analyzing issue #${issue.number} with AI`);
  
  // Create AI client based on configuration
  const aiClient = getAiClient(config.aiProvider);
  
  // Build analysis prompt based on issue context
  const prompt = buildAnalysisPrompt(issue);
  
  try {
    // Send request to AI provider
    const response = await aiClient.complete(prompt, {
      temperature: config.aiProvider.temperature || 0.2,
      maxTokens: config.aiProvider.maxTokens || 2000,
      model: config.aiProvider.model
    });
    
    logger.debug('AI analysis response received', { response });
    
    // Parse response to extract structured data
    const analysisData = parseAnalysisResponse(response, issue);
    
    return analysisData;
  } catch (error) {
    logger.error('Error analyzing issue with AI', error);
    throw new Error(`AI analysis failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Parse the AI response to extract structured analysis data
 */
function parseAnalysisResponse(response: string, issue: IssueContext): AnalysisData {
  try {
    // Simple heuristic for determining issue type from title/body
    const issueType = determineIssueType(issue);
    
    // For the MVP, we'll use a simplified analysis extraction
    // In production, we would use more sophisticated extraction techniques
    const filesToModify: string[] = [];
    let estimatedComplexity: 'simple' | 'medium' | 'complex' = 'medium';
    
    // Look for file paths in the AI response
    const filePathRegex = /`([\w\-./]+\.[\w]+)`|"([\w\-./]+\.[\w]+)"|'([\w\-./]+\.[\w]+)'/g;
    let match;
    while ((match = filePathRegex.exec(response)) !== null) {
      const filePath = match[1] || match[2] || match[3];
      if (filePath && !filesToModify.includes(filePath)) {
        filesToModify.push(filePath);
      }
    }
    
    // Determine complexity based on AI response
    if (response.toLowerCase().includes('simple') || response.toLowerCase().includes('straightforward')) {
      estimatedComplexity = 'simple';
    } else if (response.toLowerCase().includes('complex') || response.toLowerCase().includes('challenging')) {
      estimatedComplexity = 'complex';
    }
    
    // Extract suggested approach
    let suggestedApproach = '';
    if (response.includes('Suggested Approach:')) {
      suggestedApproach = response.split('Suggested Approach:')[1]?.split('\n\n')[0]?.trim() || '';
    } else if (response.includes('Approach:')) {
      suggestedApproach = response.split('Approach:')[1]?.split('\n\n')[0]?.trim() || '';
    } else {
      // Take a portion of the response as the approach
      suggestedApproach = response.split('\n\n')[0]?.trim() || '';
    }
    
    // Build analysis data object
    return {
      issueType,
      filesToModify,
      estimatedComplexity,
      requiredContext: [],
      suggestedApproach,
      confidenceScore: 0.7
    };
  } catch (error) {
    logger.error('Error parsing AI analysis response', error);
    
    // Return a fallback analysis with minimal data
    return {
      issueType: 'other',
      filesToModify: [],
      estimatedComplexity: 'medium',
      requiredContext: [],
      suggestedApproach: 'Unable to determine approach from AI analysis.'
    };
  }
}

/**
 * Determine the issue type from the issue context
 */
function determineIssueType(issue: IssueContext): IssueType {
  const title = issue.title.toLowerCase();
  const body = issue.body.toLowerCase();
  const combined = `${title} ${body}`;
  
  // Check for issue type from labels first
  for (const label of issue.labels) {
    if (label.toLowerCase().includes('bug')) return 'bug';
    if (label.toLowerCase().includes('feature')) return 'feature';
    if (label.toLowerCase().includes('refactor')) return 'refactoring';
    if (label.toLowerCase().includes('performance')) return 'performance';
    if (label.toLowerCase().includes('security')) return 'security';
    if (label.toLowerCase().includes('documentation')) return 'documentation';
    if (label.toLowerCase().includes('dependency')) return 'dependency';
    if (label.toLowerCase().includes('test')) return 'test';
  }
  
  // Check content patterns
  if (combined.includes('fix') || combined.includes('bug') || combined.includes('issue') || combined.includes('crash') || combined.includes('error')) {
    return 'bug';
  } else if (combined.includes('add') || combined.includes('new') || combined.includes('feature') || combined.includes('implement')) {
    return 'feature';
  } else if (combined.includes('refactor') || combined.includes('clean') || combined.includes('improve code')) {
    return 'refactoring';
  } else if (combined.includes('performance') || combined.includes('slow') || combined.includes('optimize') || combined.includes('speed')) {
    return 'performance';
  } else if (combined.includes('secur') || combined.includes('vulnerab') || combined.includes('hack') || combined.includes('attack')) {
    return 'security';
  } else if (combined.includes('document') || combined.includes('readme') || combined.includes('wiki') || combined.includes('comment')) {
    return 'documentation';
  } else if (combined.includes('dependency') || combined.includes('upgrade') || combined.includes('update') || combined.includes('package')) {
    return 'dependency';
  } else if (combined.includes('test') || combined.includes('spec') || combined.includes('unit test') || combined.includes('coverage')) {
    return 'test';
  }
  
  return 'other';
}