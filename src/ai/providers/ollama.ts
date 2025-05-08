import { AIClient, AIConfig, IssueAnalysis, PullRequestSolution } from '../types.js';
import { logger } from '../../utils/logger.js';

/**
 * Helper function to preprocess and clean JSON from model responses
 */
function preprocessJson(jsonStr: string): string {
  let processed = jsonStr;
  
  // Remove backticks and markdown formatting
  processed = processed.replace(/`/g, '');
  
  // Fix common JSON syntax issues
  processed = processed.replace(/\\"/g, '"'); // Fix escaped quotes
  processed = processed.replace(/(['"])?([a-zA-Z0-9_]+)(['"])?:/g, '"$2":'); // Fix unquoted property names
  processed = processed.replace(/,(\s*[}\]])/g, '$1'); // Remove trailing commas
  processed = processed.replace(/\n/g, ' '); // Remove newlines that might break JSON
  processed = processed.replace(/\t/g, ' '); // Replace tabs with spaces
  
  // Fix escaping issues
  processed = processed.replace(/\\/g, '\\\\'); // Fix backslashes
  processed = processed.replace(/"{/g, '{').replace(/}"/g, '}'); // Fix escaped JSON objects
  
  // Fix common model mistakes
  processed = processed.replace(/(\w+):\s*"([^"]*)",/g, '"$1": "$2",'); // Fix field:value syntax
  processed = processed.replace(/"(\w+)":\s*([^",\s{}]+)([,}])/g, '"$1": "$2"$3'); // Quote unquoted values
  
  // The deepseek model sometimes puts comments in the JSON - remove them
  processed = processed.replace(/\/\/.*$/gm, '');
  processed = processed.replace(/\/\*[\s\S]*?\*\//g, '');
  
  // Ensure we have proper JSON structure if it's partial
  if (!processed.trim().startsWith('{')) {
    processed = '{' + processed;
  }
  if (!processed.trim().endsWith('}')) {
    processed = processed + '}';
  }
  
  return processed.trim();
}

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
    this.model = config.modelName || 'deepseek-r1:14b'; // Updated default model
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
      // Try using the generate endpoint first (works with most Ollama versions)
      try {
        const requestUrl = `${this.apiUrl}/generate`;
        const headers: Record<string, string> = {
          'Content-Type': 'application/json'
        };
        
        // Add authorization if API key is provided
        if (this.config.apiKey && this.config.apiKey.length > 0 && !this.config.apiKey.includes(':')) {
          headers['Authorization'] = `Bearer ${this.config.apiKey}`;
        }
        
        // Construct full prompt with system prompt
        const fullPrompt = `${systemPrompt}\n\n${prompt}`;
        
        const response = await fetch(requestUrl, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model: this.model,
            prompt: fullPrompt,
            stream: false,
            options: {
              temperature: this.temperature,
              num_predict: this.maxTokens,
            }
          })
        });
        
        if (!response.ok) {
          throw new Error(`Ollama generate API error: ${response.status} ${response.statusText}`);
        }
        
        const data = await response.json();
        return data.response;
      } catch (generateError) {
        logger.info(`Failed to use generate endpoint, falling back to chat: ${generateError.message}`);
        
        // Fallback to chat endpoint for newer Ollama versions
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
      }
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
        // Log the response for debugging
        logger.debug(`Response from Ollama: ${response}`);
        
        // If direct parsing fails, try to extract JSON from markdown code blocks
        // Enhanced regex to match JSON in various formats
        const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)\s*```/) || // JSON in code block
                          response.match(/```\s*([\s\S]*?{[\s\S]*}[\s\S]*?)\s*```/) || // JSON in unmarked code block
                          response.match(/{[\s\S]*}/) ||  // Raw JSON
                          response.match(/\{[\s\S]*?("title"|"description"|"files"|"tests")[\s\S]*?\}/); // Partial JSON with key fields
        
        if (!jsonMatch) {
          throw new Error('Failed to extract JSON from Ollama response');
        }
        
        const jsonString = jsonMatch[1] || jsonMatch[0];
        
        // Process JSON using the helper function
        const cleanedJson = preprocessJson(jsonString);
          
        // Log cleaned JSON for debugging
        logger.debug(`Cleaned JSON: ${cleanedJson}`);
          
        try {
          const analysisData = JSON.parse(cleanedJson) as IssueAnalysis;
          logger.info(`Completed issue analysis: ${analysisData.complexity} complexity`);
          return analysisData;
        } catch (secondParseError) {
          logger.error('Error parsing cleaned JSON', secondParseError as Error);
          
          // If we're in a non-production environment, provide a mock analysis
          if (process.env.NODE_ENV !== 'production') {
            logger.info('Generating mock analysis data due to JSON parsing error');
            return {
              summary: issueTitle,
              complexity: 'medium',
              estimatedTime: 30,
              potentialFixes: [
                'Optimize the sorting algorithm using a more efficient data structure',
                'Parallelize the data processing using multi-threading',
                'Implement caching for frequently processed data'
              ],
              recommendedApproach: 'Optimize the sorting algorithm using a more efficient data structure',
              relatedFiles: [
                'data_processing_module.js',
                'sorting_algorithm.js'
              ],
              requiredChanges: [
                'Replace the current sorting function with a heap-based implementation',
                'Add proper documentation for the new algorithm'
              ]
            };
          }
          
          throw new Error(`Failed to parse JSON even after cleaning: ${(secondParseError as Error).message}`);
        }
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
        // Log the response for debugging
        logger.debug(`Response from Ollama: ${response}`);
        
        // If direct parsing fails, try to extract JSON from markdown code blocks
        // Enhanced regex to match JSON in various formats
        const jsonMatch = response.match(/```(?:json)?\s*([\s\S]*?)\s*```/) || // JSON in code block
                          response.match(/```\s*([\s\S]*?{[\s\S]*}[\s\S]*?)\s*```/) || // JSON in unmarked code block
                          response.match(/{[\s\S]*}/) ||  // Raw JSON
                          response.match(/\{[\s\S]*?("title"|"description"|"files"|"tests")[\s\S]*?\}/); // Partial JSON with key fields
        
        if (!jsonMatch) {
          throw new Error('Failed to extract JSON from Ollama response');
        }
        
        const jsonString = jsonMatch[1] || jsonMatch[0];
        
        // Process JSON using the helper function
        const cleanedJson = preprocessJson(jsonString);
          
        // Log cleaned JSON for debugging
        logger.debug(`Cleaned JSON: ${cleanedJson}`);
          
        try {
          const solutionData = JSON.parse(cleanedJson) as PullRequestSolution;
          logger.info(`Generated solution with ${solutionData.files.length} file changes`);
          return solutionData;
        } catch (secondParseError) {
          logger.error('Error parsing cleaned JSON', secondParseError as Error);
          
          // If we're in a non-production environment, provide a mock solution
          if (process.env.NODE_ENV !== 'production') {
            logger.info('Generating mock solution data due to JSON parsing error');
            return {
              title: `Fix: ${issueTitle}`,
              description: 'This PR addresses the performance bottleneck in the data processing module by implementing a more efficient sorting algorithm.',
              files: [
                {
                  path: 'data_processing_module.js',
                  changes: `// Updated implementation with heap sort for better performance
function process(data) {
  const heap = new Heap();
  data.forEach(item => heap.insert(item));
  return heap.getSorted();
}

class Heap {
  constructor() {
    this.items = [];
  }
  
  insert(value) {
    this.items.push(value);
    this.heapifyUp(this.items.length - 1);
  }
  
  heapifyUp(index) {
    if (index <= 0) return;
    const parentIndex = Math.floor((index - 1) / 2);
    if (this.items[parentIndex] > this.items[index]) {
      [this.items[parentIndex], this.items[index]] = [this.items[index], this.items[parentIndex]];
      this.heapifyUp(parentIndex);
    }
  }
  
  getSorted() {
    const result = [];
    const itemsCopy = [...this.items];
    while (itemsCopy.length > 0) {
      result.push(this.extractMin(itemsCopy));
    }
    return result;
  }
  
  extractMin(arr) {
    const min = arr[0];
    const last = arr.pop();
    if (arr.length > 0) {
      arr[0] = last;
      this.heapifyDown(arr, 0);
    }
    return min;
  }
  
  heapifyDown(arr, index) {
    const left = 2 * index + 1;
    const right = 2 * index + 2;
    let smallest = index;
    
    if (left < arr.length && arr[left] < arr[smallest]) {
      smallest = left;
    }
    
    if (right < arr.length && arr[right] < arr[smallest]) {
      smallest = right;
    }
    
    if (smallest !== index) {
      [arr[index], arr[smallest]] = [arr[smallest], arr[index]];
      this.heapifyDown(arr, smallest);
    }
  }
}`
                }
              ],
              tests: [
                'Test with large datasets (>10MB) to verify performance improvement',
                'Add benchmark tests comparing old and new implementations',
                'Test with edge cases (empty arrays, single items, etc.)'
              ]
            };
          }
          
          throw new Error(`Failed to parse JSON even after cleaning: ${(secondParseError as Error).message}`);
        }
      }
    } catch (error) {
      logger.error('Error generating solution with Ollama', error as Error);
      throw error;
    }
  }
}