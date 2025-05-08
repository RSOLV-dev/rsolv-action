import { IssueContext, ActionConfig, AnalysisData } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { getAiClient } from './client.js';
import { buildSolutionPrompt, getIssueTypePromptTemplate } from './prompts.js';

/**
 * Result of solution generation
 */
export interface SolutionResult {
  success: boolean;
  message: string;
  changes?: Record<string, string>;
  error?: string;
}

/**
 * Generate a solution for the issue based on AI analysis
 */
export async function generateSolution(
  issue: IssueContext,
  analysisData: AnalysisData,
  config: ActionConfig
): Promise<SolutionResult> {
  try {
    logger.info(`Generating solution for issue #${issue.number}`);
    
    // Get AI client
    const aiClient = getAiClient(config.aiProvider);
    
    // Get file contents from repository
    const fileContents = await getFilesForAnalysis(issue, analysisData);
    
    if (Object.keys(fileContents).length === 0) {
      logger.warn(`No files found for analysis in issue #${issue.number}`);
      return {
        success: false,
        message: 'No relevant files found for analysis',
      };
    }
    
    // Get issue-type specific prompt template
    const typeSpecificGuidance = getIssueTypePromptTemplate(analysisData.issueType);
    
    // Build the solution prompt
    const prompt = `${buildSolutionPrompt(issue, analysisData, fileContents)}\n\n${typeSpecificGuidance}`;
    
    // Generate solution using AI
    const response = await aiClient.complete(prompt, {
      temperature: 0.2,
      maxTokens: 4000,
      model: config.aiProvider.model
    });
    
    // Parse the solution response to extract file changes
    const changes = parseSolutionResponse(response);
    
    if (Object.keys(changes).length === 0) {
      logger.warn(`No changes extracted from solution for issue #${issue.number}`);
      return {
        success: false,
        message: 'Failed to extract file changes from AI solution',
      };
    }
    
    return {
      success: true,
      message: 'Solution generated successfully',
      changes
    };
  } catch (error) {
    logger.error(`Error generating solution for issue #${issue.number}`, error);
    return {
      success: false,
      message: `Error generating solution: ${error instanceof Error ? error.message : String(error)}`,
      error: String(error)
    };
  }
}

/**
 * Get necessary file contents from the repository
 */
async function getFilesForAnalysis(
  issue: IssueContext,
  analysisData: AnalysisData
): Promise<Record<string, string>> {
  try {
    // Start with files identified by AI analysis
    const filesToFetch = [...analysisData.filesToModify];
    
    // If no files are explicitly identified, try to infer from issue title/description
    if (filesToFetch.length === 0) {
      logger.info('No files explicitly identified, inferring from issue content');
      
      // Example logic to infer files - in a real implementation, this would be more sophisticated
      const combinedText = `${issue.title} ${issue.body}`;
      const fileExtRegex = /\.([a-zA-Z0-9]+)\b/g;
      const fileExts: string[] = [];
      let match;
      
      while ((match = fileExtRegex.exec(combinedText)) !== null) {
        if (!fileExts.includes(match[1])) {
          fileExts.push(match[1]);
        }
      }
      
      logger.debug(`Inferred file extensions: ${fileExts.join(', ')}`);
    }
    
    // Fetch content of identified files
    logger.info(`Fetching content for ${filesToFetch.length} files`);
    const fileContents: Record<string, string> = {};
    
    for (const filePath of filesToFetch) {
      try {
        // In a real implementation, this would fetch files from the GitHub repository
        // Here we just simulate the file content for demonstration purposes
        fileContents[filePath] = await simulateFileContent(filePath);
        logger.debug(`Fetched content for ${filePath}`);
      } catch (error) {
        logger.warn(`Failed to fetch content for ${filePath}`, error);
      }
    }
    
    return fileContents;
  } catch (error) {
    logger.error('Error getting files for analysis', error);
    return {};
  }
}

/**
 * Parse the AI solution response to extract file changes
 */
function parseSolutionResponse(response: string): Record<string, string> {
  const changes: Record<string, string> = {};
  
  try {
    // Look for file blocks in the response
    // Format expected: --- filepath --- followed by code blocks
    const fileBlockRegex = /---\s+([\w./-]+)\s+---\s+```[\w]*\n([\s\S]*?)```/g;
    let match;
    
    while ((match = fileBlockRegex.exec(response)) !== null) {
      const [, filePath, content] = match;
      if (filePath && content) {
        changes[filePath] = content.trim();
      }
    }
    
    // If the above pattern doesn't match, try alternative formats
    if (Object.keys(changes).length === 0) {
      // Alternative format: ```filepath content ```
      const altFileBlockRegex = /```(?:file|filepath)\s+([\w./-]+)\n([\s\S]*?)```/g;
      while ((match = altFileBlockRegex.exec(response)) !== null) {
        const [, filePath, content] = match;
        if (filePath && content) {
          changes[filePath] = content.trim();
        }
      }
    }
    
    return changes;
  } catch (error) {
    logger.error('Error parsing solution response', error);
    return {};
  }
}

/**
 * Simulate fetching file content for development
 */
async function simulateFileContent(filePath: string): Promise<string> {
  // Add a small delay to simulate network latency
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Mock content based on file extension
  const ext = filePath.split('.').pop()?.toLowerCase();
  
  switch (ext) {
  case 'js':
    return `// Example JavaScript file content for ${filePath}\nfunction processData(input) {\n  // TODO: Implement proper validation\n  return input.map(item => item.value);\n}\n\nmodule.exports = { processData };\n`;
      
  case 'ts':
    return `// Example TypeScript file content for ${filePath}\ninterface DataItem {\n  id: string;\n  value: number;\n}\n\nfunction processData(input: DataItem[]): number[] {\n  // TODO: Implement proper validation\n  return input.map(item => item.value);\n}\n\nexport { DataItem, processData };\n`;
      
  case 'py':
    return `# Example Python file content for ${filePath}\ndef process_data(input_data):\n    # TODO: Implement proper validation\n    return [item['value'] for item in input_data]\n\nif __name__ == "__main__":\n    print(process_data([{'value': 1}, {'value': 2}]))\n`;
      
  case 'md':
    return `# Documentation for ${filePath.split('/').pop()?.replace('.md', '')}\n\n## Overview\n\nThis documentation describes the usage and implementation details.\n\n## Installation\n\n\`\`\`bash\nnpm install example-package\n\`\`\`\n\n## Usage\n\n\`\`\`javascript\nconst { processData } = require('example-package');\nconst result = processData([{ id: '1', value: 42 }]);\n\`\`\`\n`;
      
  default:
    return `// Example file content for ${filePath}\n// This is a placeholder for demonstration purposes\n`;
  }
}