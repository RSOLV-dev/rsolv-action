import { logger } from '../utils/logger.js';

interface Label {
  name: string;
  color: string;
  description: string;
}

const REQUIRED_LABELS: Label[] = [
  {
    name: 'rsolv:detected',
    color: 'FBCA04',
    description: 'Issue detected by RSOLV security scan'
  },
  {
    name: 'rsolv:validate', 
    color: '0E8A16',
    description: 'Trigger RSOLV validation phase'
  },
  {
    name: 'rsolv:automate',
    color: '0052CC', 
    description: 'Trigger RSOLV fix generation'
  },
  {
    name: 'security',
    color: 'D93F0B',
    description: 'Security vulnerability'
  },
  {
    name: 'automated-scan',
    color: 'C5DEF5',
    description: 'Created by automated security scan'
  },
  {
    name: 'critical',
    color: 'B60205',
    description: 'Critical severity'
  },
  {
    name: 'high',
    color: 'D93F0B', 
    description: 'High severity'
  },
  {
    name: 'medium',
    color: 'FBCA04',
    description: 'Medium severity'
  },
  {
    name: 'low',
    color: '0E8A16',
    description: 'Low severity'
  }
];

/**
 * Ensures all required labels exist in the repository
 * Creates any missing labels automatically
 */
export async function ensureLabelsExist(
  owner: string,
  repo: string,
  token: string
): Promise<void> {
  logger.info('Ensuring required labels exist...');
  
  const headers = {
    'Authorization': `token ${token}`,
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json'
  };

  try {
    // Get existing labels
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/labels`,
      { headers }
    );
    
    if (!response.ok) {
      logger.warn(`Failed to fetch labels: ${response.status}. Skipping label creation.`);
      return;
    }
    
    const existingLabels = await response.json() as Array<{ name: string }>;
    const existingNames = new Set(existingLabels.map(l => l.name.toLowerCase()));
    
    // Create missing labels
    for (const label of REQUIRED_LABELS) {
      if (!existingNames.has(label.name.toLowerCase())) {
        logger.info(`Creating missing label: ${label.name}`);
        
        const createResponse = await fetch(
          `https://api.github.com/repos/${owner}/${repo}/labels`,
          {
            method: 'POST',
            headers,
            body: JSON.stringify({
              name: label.name,
              color: label.color,
              description: label.description
            })
          }
        );
        
        if (!createResponse.ok) {
          const error = await createResponse.text();
          logger.warn(`Failed to create label ${label.name}: ${error}`);
        } else {
          logger.info(`✅ Created label: ${label.name}`);
        }
      }
    }
    
    logger.info('Label check complete');
  } catch (error) {
    logger.error('Failed to ensure labels exist', error);
    // Don't fail the action if label creation fails
  }
}