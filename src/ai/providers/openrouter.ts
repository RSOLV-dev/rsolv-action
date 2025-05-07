import { AIClient, AIConfig, IssueAnalysis, PullRequestSolution } from '../types.js';
import { logger } from '../../utils/logger.js';

/**
 * Client for OpenRouter, which provides access to multiple AI models
 */
export class OpenRouterClient implements AIClient {
  private config: AIConfig;
  private model: string;
  private temperature: number;
  private maxTokens: number;
  private apiUrl: string = 'https://openrouter.ai/api/v1/chat/completions';

  constructor(config: AIConfig) {
    this.config = config;
    this.model = config.modelName || 'anthropic/claude-3-sonnet';
    this.temperature = config.temperature !== undefined ? config.temperature : 0.2;
    this.maxTokens = config.maxTokens || 4000;
    
    // Validate API key
    if (!config.apiKey || config.apiKey.length < 20) {
      throw new Error('Invalid OpenRouter API key provided');
    }

    logger.info(`Initialized OpenRouter AI client with model: ${this.model}`);
  }

  /**
   * Make a request to the OpenRouter API
   */
  private async callAPI(prompt: string, systemPrompt: string = 'You are RSOLV, an AI-powered system for automatically fixing software issues.'): Promise<string> {
    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`,
          'HTTP-Referer': 'https://rsolv.dev',
          'X-Title': 'RSOLV Action'
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: this.maxTokens,
          temperature: this.temperature,
          messages: [
            {
              role: 'system',
              content: systemPrompt
            },
            {
              role: 'user',
              content: prompt
            }
          ]
        })
      });

      if (!response.ok) {
        throw new Error(`OpenRouter API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data.choices[0].message.content;
    } catch (error) {
      logger.error('Error calling OpenRouter API', error as Error);
      throw error;
    }
  }

  /**
   * Analyze an issue to determine complexity and approaches
   */
  async analyzeIssue(
    issueTitle: string,
    issueBody: string,
    repoContext?: any
  ): Promise<IssueAnalysis> {
    try {
      // Construct the prompt for issue analysis
      const prompt = `
Please analyze the following software issue:

Title: ${issueTitle}

Description:
${issueBody}

${repoContext ? `Repository context:\n${JSON.stringify(repoContext, null, 2)}\n` : ''}

Please analyze this issue and provide the following information in a structured format:
1. A brief summary of the issue
2. The estimated complexity (low, medium, high)
3. Estimated time to fix (in minutes)
4. Potential approaches to fixing the issue
5. The recommended approach
6. Any related files that might need to be modified
7. Specific changes required

Format your response as valid JSON with the following structure:
{
  "summary": "Brief summary of the issue",
  "complexity": "low|medium|high",
  "estimatedTime": number,
  "potentialFixes": ["approach 1", "approach 2", ...],
  "recommendedApproach": "The best approach to take",
  "relatedFiles": ["file1.js", "file2.js", ...],
  "requiredChanges": ["Change X to Y", "Add function Z", ...]
}

Your response must be valid JSON only, with no other text.
`;

      // Call OpenRouter API
      logger.info('Requesting issue analysis from OpenRouter');
      const response = await this.callAPI(prompt);
      
      try {
        // Try to parse the response directly as JSON first
        const analysisData = JSON.parse(response) as IssueAnalysis;
        logger.info(`Completed issue analysis: ${analysisData.complexity} complexity`);
        return analysisData;
      } catch (parseError) {
        // If direct parsing fails, try to extract JSON from markdown code blocks
        const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)\s*```/) || 
                          response.match(/{[\s\S]*}/);
        
        if (!jsonMatch) {
          throw new Error('Failed to extract JSON from API response');
        }
        
        const jsonString = jsonMatch[1] || jsonMatch[0];
        const analysisData = JSON.parse(jsonString) as IssueAnalysis;
        
        logger.info(`Completed issue analysis: ${analysisData.complexity} complexity`);
        return analysisData;
      }
      
    } catch (error) {
      logger.error('Error analyzing issue with OpenRouter', error as Error);
      throw error;
    }
  }

  /**
   * Generate a solution for an issue
   */
  async generateSolution(
    issueTitle: string,
    issueBody: string,
    issueAnalysis: IssueAnalysis,
    repoContext?: any
  ): Promise<PullRequestSolution> {
    try {
      // Construct the prompt for solution generation
      const prompt = `
Please generate a solution for the following software issue:

Title: ${issueTitle}

Description:
${issueBody}

Analysis:
${JSON.stringify(issueAnalysis, null, 2)}

${repoContext ? `Repository context:\n${JSON.stringify(repoContext, null, 2)}\n` : ''}

Based on the issue and analysis, please generate a solution with the following:
1. A descriptive PR title
2. A detailed PR description explaining the changes
3. The code changes required for each file
4. Any tests that should be added or modified

Format your response as valid JSON with the following structure:
{
  "title": "Fix: descriptive PR title",
  "description": "Detailed explanation of the changes",
  "files": [
    {
      "path": "path/to/file.js",
      "changes": "Complete code for the file or a clear description of changes"
    }
  ],
  "tests": [
    "Description of test 1",
    "Description of test 2"
  ]
}

Your response must be valid JSON only, with no other text.
`;

      // Call OpenRouter API
      logger.info('Requesting solution generation from OpenRouter');
      const response = await this.callAPI(prompt);
      
      try {
        // Try to parse the response directly as JSON first
        const solutionData = JSON.parse(response) as PullRequestSolution;
        logger.info(`Generated solution with ${solutionData.files.length} file changes`);
        return solutionData;
      } catch (parseError) {
        // If direct parsing fails, try to extract JSON from markdown code blocks
        const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)\s*```/) || 
                          response.match(/{[\s\S]*}/);
        
        if (!jsonMatch) {
          throw new Error('Failed to extract JSON from API response');
        }
        
        const jsonString = jsonMatch[1] || jsonMatch[0];
        const solutionData = JSON.parse(jsonString) as PullRequestSolution;
        
        logger.info(`Generated solution with ${solutionData.files.length} file changes`);
        return solutionData;
      }
      
    } catch (error) {
      logger.error('Error generating solution with OpenRouter', error as Error);
      throw error;
    }
  }
}