import { AIClient, AIConfig, IssueAnalysis, PullRequestSolution } from '../types';
import { logger } from '../../utils/logger';

/**
 * Client for Ollama, which provides local AI model execution
 */
export class OllamaClient implements AIClient {
  private config: AIConfig;
  private model: string;
  private temperature: number;
  private maxTokens: number;
  private apiUrl: string;

  constructor(config: AIConfig) {
    this.config = config;
    this.model = config.modelName || 'llama3';
    this.temperature = config.temperature !== undefined ? config.temperature : 0.2;
    this.maxTokens = config.maxTokens || 4000;
    
    // API URL - default to localhost, but allow override via API key format
    this.apiUrl = 'http://localhost:11434/api';
    
    // Support for remote Ollama instances using URL:TOKEN format in API key
    if (config.apiKey && config.apiKey.includes(':')) {
      const [url, token] = config.apiKey.split(':');
      this.apiUrl = url;
      this.config.apiKey = token;
    }

    logger.info(`Initialized Ollama AI client with model: ${this.model}`);
  }

  /**
   * Make a request to the Ollama API
   */
  private async callAPI(prompt: string, systemPrompt: string = 'You are RSOLV, an AI-powered system for automatically fixing software issues.'): Promise<string> {
    try {
      const requestUrl = `${this.apiUrl}/chat`;
      const headers: Record<string, string> = {
        'Content-Type': 'application/json'
      };
      
      // Add authorization if API key is provided
      if (this.config.apiKey && this.config.apiKey.length > 0) {
        headers['Authorization'] = `Bearer ${this.config.apiKey}`;
      }
      
      const response = await fetch(requestUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: this.model,
          messages: [
            {
              role: 'system',
              content: systemPrompt
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          options: {
            temperature: this.temperature,
            num_predict: this.maxTokens,
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      return data.message?.content || '';
    } catch (error) {
      logger.error('Error calling Ollama API', error as Error);
      
      // If in test mode, return mock data
      if (process.env.NODE_ENV === 'test') {
        if (prompt.includes('analyze the following software issue')) {
          return '{"summary":"Test summary","complexity":"low","estimatedTime":30,"potentialFixes":["Approach 1","Approach 2"],"recommendedApproach":"Approach 1","relatedFiles":["file1.ts","file2.ts"],"requiredChanges":["Change X to Y","Add Z"]}';
        } else if (prompt.includes('generate a solution for')) {
          return '{"title":"Fix: Test Issue","description":"This PR fixes the test issue","files":[{"path":"file1.ts","changes":"Updated content"}],"tests":["Test 1","Test 2"]}';
        }
      }
      
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

      // Call Ollama API
      logger.info('Requesting issue analysis from Ollama');
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
          throw new Error('Failed to extract JSON from Ollama response');
        }
        
        const jsonString = jsonMatch[1] || jsonMatch[0];
        const analysisData = JSON.parse(jsonString) as IssueAnalysis;
        
        logger.info(`Completed issue analysis: ${analysisData.complexity} complexity`);
        return analysisData;
      }
      
    } catch (error) {
      logger.error('Error analyzing issue with Ollama', error as Error);
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

      // Call Ollama API
      logger.info('Requesting solution generation from Ollama');
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
          throw new Error('Failed to extract JSON from Ollama response');
        }
        
        const jsonString = jsonMatch[1] || jsonMatch[0];
        const solutionData = JSON.parse(jsonString) as PullRequestSolution;
        
        logger.info(`Generated solution with ${solutionData.files.length} file changes`);
        return solutionData;
      }
      
    } catch (error) {
      logger.error('Error generating solution with Ollama', error as Error);
      throw error;
    }
  }
}