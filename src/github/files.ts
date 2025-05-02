import { logger } from '../utils/logger';
import { IssueContext } from '../types/index';
import { getGitHubClient } from './api';

/**
 * Get repository files based on the file paths
 */
export async function getRepositoryFiles(
  issue: IssueContext,
  filePaths: string[]
): Promise<Record<string, string>> {
  try {
    logger.info(`Fetching ${filePaths.length} files from repository ${issue.repository.fullName}`);
    
    const fileContents: Record<string, string> = {};
    
    // Get GitHub client
    const github = getGitHubClient();
    const { owner, name: repo } = issue.repository;
    
    // Process files in batches to avoid rate limiting (5 files at a time)
    const batchSize = 5;
    for (let i = 0; i < filePaths.length; i += batchSize) {
      const batch = filePaths.slice(i, i + batchSize);
      
      // Process batch in parallel
      await Promise.all(batch.map(async (filePath) => {
        try {
          // Use GitHub API to fetch file content
          if (process.env.NODE_ENV === 'test') {
            // Use mock content in test mode
            fileContents[filePath] = await simulateFileContent(filePath, issue);
            return;
          }
          
          const response = await github.repos.getContent({
            owner,
            repo,
            path: filePath,
            ref: issue.repository.defaultBranch
          });
          
          // Check if response is a file (not a directory)
          if (Array.isArray(response.data)) {
            throw new Error(`Path ${filePath} is a directory, not a file`);
          }
          
          // Extract and decode content
          const content = response.data.content;
          if (content) {
            // GitHub API returns base64 encoded content
            fileContents[filePath] = Buffer.from(content, 'base64').toString('utf-8');
            logger.debug(`Fetched content for ${filePath}`);
          } else {
            throw new Error(`No content returned for ${filePath}`);
          }
        } catch (error) {
          // If API call fails in development, fall back to mock content
          if (process.env.NODE_ENV === 'development') {
            logger.warn(`Failed to fetch content for ${filePath}, using mock content`, error);
            fileContents[filePath] = await simulateFileContent(filePath, issue);
          } else {
            logger.warn(`Failed to fetch content for ${filePath}`, error);
          }
        }
      }));
      
      // Small delay between batches to avoid rate limiting
      if (i + batchSize < filePaths.length) {
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    
    return fileContents;
  } catch (error) {
    logger.error(`Error fetching repository files for ${issue.repository.fullName}`, error);
    
    // In development or test mode, fall back to simulated files
    if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
      logger.warn('Using simulated file content due to error');
      
      const fileContents: Record<string, string> = {};
      for (const filePath of filePaths) {
        fileContents[filePath] = await simulateFileContent(filePath, issue);
      }
      return fileContents;
    }
    
    throw new Error(`Failed to fetch repository files: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Simulate fetching file content for development
 */
async function simulateFileContent(filePath: string, issue: IssueContext): Promise<string> {
  // Add a small delay to simulate network latency
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Mock content based on file extension
  const ext = filePath.split('.').pop()?.toLowerCase();
  
  switch (ext) {
    case 'js':
      return `// JavaScript file in ${issue.repository.name}: ${filePath}
const { Logger } = require('../utils/logger');
const logger = new Logger();

/**
 * Process data function
 * @param {Array} input - Input data to process
 * @returns {Array} - Processed data
 */
function processData(input) {
  logger.debug(\`Processing \${input.length} items\`);
  
  if (!Array.isArray(input)) {
    logger.error('Input must be an array');
    throw new Error('Input must be an array');
  }
  
  return input.map(item => {
    if (!item || typeof item !== 'object' || !('value' in item)) {
      logger.warn('Invalid item structure, missing value property');
      return null;
    }
    return item.value;
  }).filter(Boolean);
}

module.exports = { processData };
`;
      
    case 'ts':
      return `// TypeScript file in ${issue.repository.name}: ${filePath}
import { Logger } from '../utils/logger';
const logger = new Logger();

/**
 * Data item interface
 */
interface DataItem {
  id: string;
  value: number;
  metadata?: Record<string, any>;
}

/**
 * Process data function
 * @param input - Input data to process
 * @returns Processed data array
 */
function processData(input: DataItem[]): number[] {
  logger.debug(\`Processing \${input.length} items\`);
  
  return input
    .filter(item => {
      if (!item || typeof item.value !== 'number') {
        logger.warn(\`Invalid item structure: \${JSON.stringify(item)}\`);
        return false;
      }
      return true;
    })
    .map(item => item.value);
}

export { DataItem, processData };
`;
      
    case 'py':
      return `# Python file in ${issue.repository.name}: ${filePath}
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

def process_data(input_data: List[Dict[str, Any]]) -> List[Optional[int]]:
    """
    Process input data and extract values
    
    Args:
        input_data: List of dictionaries containing data items
        
    Returns:
        List of extracted values
    """
    logger.debug(f"Processing {len(input_data)} items")
    
    result = []
    for item in input_data:
        if not isinstance(item, dict) or 'value' not in item:
            logger.warning(f"Invalid item structure: {item}")
            result.append(None)
            continue
            
        try:
            result.append(int(item['value']))
        except (ValueError, TypeError):
            logger.error(f"Could not convert value to int: {item['value']}")
            result.append(None)
            
    return result

if __name__ == "__main__":
    test_data = [{'id': '1', 'value': 42}, {'id': '2', 'value': '123'}, {'id': '3'}]
    print(process_data(test_data))
`;
      
    case 'md':
      return `# Documentation for ${filePath.split('/').pop()?.replace('.md', '')}

## Overview

This documentation describes the usage and implementation details of the data processing module in ${issue.repository.name}.

## Installation

\`\`\`bash
npm install @${issue.repository.owner}/${issue.repository.name}
\`\`\`

## Usage

\`\`\`javascript
const { processData } = require('@${issue.repository.owner}/${issue.repository.name}');

const data = [
  { id: '1', value: 42 },
  { id: '2', value: 17 }
];

const result = processData(data);
console.log(result); // [42, 17]
\`\`\`

## Error Handling

The function will filter out invalid items from the results and log warnings.
`;
      
    default:
      return `// Example file content for ${filePath} in ${issue.repository.name}
// This is a placeholder for demonstration purposes
`;
  }
}