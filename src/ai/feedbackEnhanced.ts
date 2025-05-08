import { IssueContext } from '../types/index.js';
import { IssueAnalysis, PullRequestSolution, AIConfig } from './types.js';
import { getAiClient } from './client.js';
import { logger } from '../utils/logger.js';
import { promptEnhancer } from '../feedback/index.js';

/**
 * Generate a solution for an issue with feedback enhancement
 * This is an enhanced version of generateSolution that uses the feedback system
 * to improve prompt quality based on historical feedback
 */
export async function generateSolutionWithFeedback(
  issueContext: IssueContext,
  analysis: IssueAnalysis,
  aiConfig: AIConfig
): Promise<PullRequestSolution> {
  try {
    logger.info(`Generating feedback-enhanced solution for issue: ${issueContext.id}`);
    
    // Get the AI client
    const aiClient = getAiClient(aiConfig);
    
    // Extract repository context
    const repoContext = {
      owner: issueContext.repository.owner,
      name: issueContext.repository.name,
      defaultBranch: issueContext.repository.defaultBranch,
      source: issueContext.source,
    };
    
    // Generate enhancement context from historical feedback
    const enhancementContext = await promptEnhancer.generateEnhancementContext(issueContext);
    
    logger.info(`Generated enhancement context with ${enhancementContext.relevantFeedback.length} feedback items`);
    
    // Create a enhanced version of the AI client that incorporates feedback
    const enhancedClient = {
      ...aiClient,
      generateSolution: async (
        issueTitle: string,
        issueBody: string,
        issueAnalysis: IssueAnalysis,
        repoContext: any
      ): Promise<PullRequestSolution> => {
        // For providers that support custom prompts, we can enhance their prompts directly
        // For now, we'll add the feedback context to the issue body
        
        // Create a base prompt for the AI
        const basePrompt = `
Issue Title: ${issueTitle}
Issue Description: ${issueBody}

Analysis:
- Complexity: ${issueAnalysis.complexity}
- Recommended Approach: ${issueAnalysis.recommendedApproach}
- Required Changes: ${issueAnalysis.requiredChanges?.join(', ') || 'None specified'}
`;
        
        // Enhance the prompt with feedback patterns
        const enhancedPrompt = promptEnhancer.enhancePrompt(basePrompt, enhancementContext);
        
        // Calculate if we added significant enhancements
        const hasSignificantEnhancements = 
          enhancedPrompt.length > basePrompt.length + 100;
          
        logger.info(`Created ${hasSignificantEnhancements ? 'enhanced' : 'standard'} prompt for AI solution generation`);
        
        // Check if we're using Claude Code adapter (which has a different interface)
        if (aiConfig.useClaudeCode) {
          logger.info('Using Claude Code with feedback-enhanced prompt');
          
          // The ClaudeCodeWrapper will already have created an issueContext
          // We'll pass the enhanced prompt directly to the wrapped adapter
          return aiClient.generateSolution(
            issueTitle,
            enhancedPrompt, // Pass the enhanced prompt as the issue body
            issueAnalysis,
            repoContext
          );
        } else {
          // Standard AI providers
          // Use the enhanced prompt as the issue body
          return aiClient.generateSolution(
            issueTitle,
            enhancedPrompt,
            issueAnalysis,
            repoContext
          );
        }
      }
    };
    
    // Generate the solution using the enhanced client
    const solution = await enhancedClient.generateSolution(
      issueContext.title,
      issueContext.body,
      analysis,
      repoContext
    );
    
    logger.info(`Feedback-enhanced solution generated with ${solution.files.length} file changes`);
    
    return solution;
    
  } catch (error) {
    logger.error('Error generating feedback-enhanced solution', error as Error);
    
    // Fall back to standard solution generation if feedback enhancement fails
    logger.info('Falling back to standard solution generation');
    
    // Import the standard solution generator
    const { generateSolution } = await import('./solution.js');
    
    return generateSolution(issueContext, analysis, aiConfig);
  }
}