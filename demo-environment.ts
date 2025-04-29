#!/usr/bin/env bun
/**
 * RSOLV Demo Environment
 * 
 * This script provides a comprehensive demo environment for manually exercising
 * all components of the RSOLV system, including:
 * - Issue Analysis
 * - Solution Generation
 * - PR Creation
 * - Feedback Collection & Processing
 * - Prompt Enhancement based on feedback
 */
import { Command } from 'commander';
import { Octokit } from '@octokit/rest';
import readline from 'readline';
import { v4 as uuidv4 } from 'uuid';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';

// Import RSOLV components
import { GitHubApiClient } from './src/github/api';
import { GitHubPRManager } from './src/github/pr';
import { generateSolution } from './src/ai/solution';
import { analyzeIssue } from './src/ai/analyzer';
import { AIConfig } from './src/ai/types';
import { IssueContext, IssueAnalysis } from './src/types';
import { 
  feedbackStorage, 
  feedbackCollector, 
  promptEnhancer, 
  FeedbackEvent,
  FeedbackSentiment,
  ActionTaken 
} from './src/feedback';

// Set up interactive readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Create CLI program
const program = new Command();

// Initialize storage path for demo data
const DEMO_DATA_DIR = path.join(process.cwd(), 'demo-data');
if (!fs.existsSync(DEMO_DATA_DIR)) {
  fs.mkdirSync(DEMO_DATA_DIR, { recursive: true });
}

// Initialize feedback storage
const FEEDBACK_PATH = path.join(DEMO_DATA_DIR, 'feedback.json');

// Function to initialize demo environment
async function initializeDemo() {
  try {
    console.log(chalk.blue('🚀 Initializing RSOLV Demo Environment'));

    // Initialize feedback storage
    await feedbackStorage.initialize();
    console.log(chalk.green('✅ Feedback system initialized'));

    return true;
  } catch (error) {
    console.error(chalk.red('❌ Error initializing demo environment:'), error);
    return false;
  }
}

// Function to get GitHub token from environment or prompt
async function getGitHubToken(): Promise<string> {
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    return token;
  }

  return new Promise((resolve) => {
    rl.question(chalk.yellow('Enter your GitHub token: '), (answer) => {
      resolve(answer.trim());
    });
  });
}

// Function to get AI config (model, API key)
async function getAIConfig(): Promise<AIConfig> {
  // Get provider from env or prompt
  let provider = process.env.AI_PROVIDER || 'anthropic';
  let apiKey = '';
  let modelName = '';

  // If provider not in env, ask user
  if (!process.env.AI_PROVIDER) {
    const providerAnswer = await new Promise<string>((resolve) => {
      rl.question(
        chalk.yellow('Select AI provider (anthropic, openrouter, ollama) [default: anthropic]: '),
        (answer) => {
          resolve(answer.trim() || 'anthropic');
        }
      );
    });
    provider = providerAnswer;
  }

  // Set appropriate API key and model based on provider
  switch (provider) {
    case 'anthropic':
      apiKey = process.env.ANTHROPIC_API_KEY || await new Promise<string>((resolve) => {
        rl.question(chalk.yellow('Enter your Anthropic API key: '), (answer) => {
          resolve(answer.trim());
        });
      });
      modelName = 'claude-3-opus-20240229';
      break;
    case 'openrouter':
      apiKey = process.env.OPENROUTER_API_KEY || await new Promise<string>((resolve) => {
        rl.question(chalk.yellow('Enter your OpenRouter API key: '), (answer) => {
          resolve(answer.trim());
        });
      });
      modelName = 'anthropic/claude-3-opus';
      break;
    case 'ollama':
      apiKey = process.env.OLLAMA_API_KEY || await new Promise<string>((resolve) => {
        rl.question(chalk.yellow('Enter your Ollama API key (can be URL:TOKEN format): '), (answer) => {
          resolve(answer.trim());
        });
      });
      modelName = process.env.OLLAMA_MODEL || 'llama3';
      break;
    default:
      apiKey = process.env.ANTHROPIC_API_KEY || await new Promise<string>((resolve) => {
        rl.question(chalk.yellow('Enter your Anthropic API key: '), (answer) => {
          resolve(answer.trim());
        });
      });
      modelName = 'claude-3-opus-20240229';
  }

  return {
    provider: provider as any,
    apiKey,
    modelName
  };
}

// Function to get issue details either from GitHub or manual input
async function getIssueContext(): Promise<IssueContext> {
  const sourceType = await new Promise<string>((resolve) => {
    rl.question(
      chalk.yellow('Use [1] GitHub issue URL or [2] Manual issue input? [1/2]: '),
      (answer) => {
        resolve(answer.trim() === '2' ? 'manual' : 'github');
      }
    );
  });

  if (sourceType === 'github') {
    const issueUrl = await new Promise<string>((resolve) => {
      rl.question(chalk.yellow('Enter GitHub issue URL: '), (answer) => {
        resolve(answer.trim());
      });
    });

    // Parse the issue URL
    const issueUrlRegex = /github\.com\/([^\/]+)\/([^\/]+)\/issues\/(\d+)/;
    const match = issueUrl.match(issueUrlRegex);
    if (!match) {
      throw new Error('Invalid GitHub issue URL. Expected format: https://github.com/owner/repo/issues/123');
    }

    const [, owner, repo, issueNumber] = match;
    
    // Get GitHub token
    const token = await getGitHubToken();
    
    // Initialize GitHub client
    const apiClient = new GitHubApiClient(token, owner, repo);
    
    // Get issue details
    console.log(chalk.blue('📥 Fetching issue details...'));
    const { data: issue } = await apiClient.getOctokit().rest.issues.get({
      owner,
      repo,
      issue_number: parseInt(issueNumber, 10)
    });
    
    // Create issue context
    return {
      id: issueNumber,
      source: 'github',
      title: issue.title,
      body: issue.body || '',
      labels: issue.labels?.map((label: any) => 
        typeof label === 'string' ? label : label.name
      ) || [],
      repository: {
        owner,
        repo,
        branch: 'main' // Assuming main branch
      },
      metadata: {
        htmlUrl: issue.html_url,
        user: issue.user.login,
        state: issue.state,
        createdAt: issue.created_at,
        updatedAt: issue.updated_at
      },
      url: issue.html_url
    };
  } else {
    // Manual issue input
    const issueTitle = await new Promise<string>((resolve) => {
      rl.question(chalk.yellow('Enter issue title: '), (answer) => {
        resolve(answer.trim());
      });
    });

    const issueBody = await new Promise<string>((resolve) => {
      rl.question(chalk.yellow('Enter issue description: '), (answer) => {
        resolve(answer.trim());
      });
    });

    const repoOwner = await new Promise<string>((resolve) => {
      rl.question(chalk.yellow('Enter repository owner: '), (answer) => {
        resolve(answer.trim());
      });
    });

    const repoName = await new Promise<string>((resolve) => {
      rl.question(chalk.yellow('Enter repository name: '), (answer) => {
        resolve(answer.trim());
      });
    });

    // Generate a unique issue ID for the demo
    const issueId = `demo-${Date.now()}`;

    return {
      id: issueId,
      source: 'demo',
      title: issueTitle,
      body: issueBody,
      labels: ['AUTOFIX', 'demo'],
      repository: {
        owner: repoOwner,
        repo: repoName,
        branch: 'main'
      },
      metadata: {
        htmlUrl: `https://github.com/${repoOwner}/${repoName}/issues/${issueId}`,
        user: 'demo-user',
        state: 'open',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      },
      url: `https://github.com/${repoOwner}/${repoName}/issues/${issueId}`
    };
  }
}

// Save demo state to file for later resumption
function saveDemoState(data: any) {
  try {
    fs.writeFileSync(
      path.join(DEMO_DATA_DIR, 'demo-state.json'),
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    console.error(chalk.red('Error saving demo state:'), error);
  }
}

// Load previous demo state if available
function loadDemoState(): any {
  try {
    const statePath = path.join(DEMO_DATA_DIR, 'demo-state.json');
    if (fs.existsSync(statePath)) {
      return JSON.parse(fs.readFileSync(statePath, 'utf8'));
    }
  } catch (error) {
    console.error(chalk.red('Error loading demo state:'), error);
  }
  return null;
}

// Display a simple menu and get user choice
async function showMenu(options: string[]): Promise<number> {
  console.log(chalk.blue('\n📋 Available Actions:'));
  
  options.forEach((option, index) => {
    console.log(chalk.cyan(`${index + 1}. ${option}`));
  });
  
  const choice = await new Promise<string>((resolve) => {
    rl.question(chalk.yellow('\nEnter your choice (number): '), (answer) => {
      resolve(answer.trim());
    });
  });
  
  const choiceNum = parseInt(choice, 10);
  if (isNaN(choiceNum) || choiceNum < 1 || choiceNum > options.length) {
    console.log(chalk.red('Invalid choice. Please try again.'));
    return showMenu(options);
  }
  
  return choiceNum;
}

// Simulate PR feedback collection
async function simulateFeedback(
  issueContext: IssueContext,
  prNumber: string
): Promise<void> {
  console.log(chalk.blue('\n💬 Feedback Simulation'));
  console.log('This will simulate feedback for the generated PR to demonstrate the feedback loop system.');
  
  // Reviewer information
  const reviewerName = await new Promise<string>((resolve) => {
    rl.question(chalk.yellow('Enter reviewer name [default: Expert Reviewer]: '), (answer) => {
      resolve(answer.trim() || 'Expert Reviewer');
    });
  });
  
  const reviewerId = `demo-${uuidv4().substring(0, 8)}`;
  const reviewerRole = 'expert';
  
  // Get feedback type
  const feedbackTypeOptions = ['Comment', 'Review', 'Edit', 'Approve', 'Reject'];
  const feedbackTypeIndex = await showMenu(feedbackTypeOptions);
  const feedbackType = feedbackTypeOptions[feedbackTypeIndex - 1].toLowerCase() as any;
  
  // Get feedback sentiment
  const sentimentOptions = ['Positive', 'Negative', 'Neutral'];
  const sentimentIndex = await showMenu(sentimentOptions);
  const sentiment = sentimentOptions[sentimentIndex - 1].toLowerCase() as FeedbackSentiment;
  
  // Get feedback content
  const feedbackContent = await new Promise<string>((resolve) => {
    rl.question(chalk.yellow('Enter feedback content: '), (answer) => {
      resolve(answer.trim());
    });
  });
  
  // Create action taken based on feedback type and sentiment
  let actionTaken: ActionTaken | undefined;
  if (feedbackType === 'approve') {
    actionTaken = 'accepted';
  } else if (feedbackType === 'reject') {
    actionTaken = 'rejected';
  } else if (feedbackType === 'edit' || (feedbackType === 'review' && sentiment === 'negative')) {
    actionTaken = 'modified';
  } else if (sentiment === 'positive') {
    actionTaken = 'accepted';
  }
  
  // Create feedback event
  const feedbackEvent: Omit<FeedbackEvent, 'id'> = {
    issueId: issueContext.id,
    prId: prNumber,
    reviewer: {
      id: reviewerId,
      name: reviewerName,
      role: reviewerRole
    },
    timestamp: new Date().toISOString(),
    type: feedbackType,
    content: feedbackContent,
    context: {},
    sentiment,
    actionTaken
  };
  
  // Add modifications if this is an edit
  if (feedbackType === 'edit') {
    feedbackEvent.modifications = {
      before: 'Original content (simulated)',
      after: 'Modified content with improvements (simulated)'
    };
  }
  
  // Store the feedback
  const createdFeedback = await feedbackStorage.createFeedback(feedbackEvent);
  
  console.log(chalk.green('\n✅ Feedback stored successfully!'));
  console.log('Feedback ID:', chalk.cyan(createdFeedback.id));
  console.log('Type:', chalk.cyan(createdFeedback.type));
  console.log('Sentiment:', chalk.cyan(createdFeedback.sentiment));
  console.log('Action Taken:', chalk.cyan(createdFeedback.actionTaken || 'none'));
}

// Display feedback statistics
async function displayFeedbackStats(): Promise<void> {
  console.log(chalk.blue('\n📊 Feedback Statistics'));
  
  const stats = await feedbackStorage.getStats();
  
  console.log(chalk.cyan('\nOverview:'));
  console.log(`Total Feedback: ${stats.totalFeedback}`);
  console.log(`Positive Feedback: ${stats.positiveFeedback}`);
  console.log(`Negative Feedback: ${stats.negativeFeedback}`);
  console.log(`Neutral Feedback: ${stats.neutralFeedback}`);
  
  console.log(chalk.cyan('\nBy Type:'));
  for (const [type, count] of Object.entries(stats.byType)) {
    console.log(`${type}: ${count}`);
  }
  
  console.log(chalk.cyan('\nBy Action:'));
  for (const [action, count] of Object.entries(stats.byAction)) {
    console.log(`${action}: ${count}`);
  }
  
  console.log(chalk.cyan('\nFeedback Timeline:'));
  stats.feedbackOverTime.forEach(entry => {
    console.log(`${entry.date}: ${entry.count} feedbacks (👍 ${entry.sentiment.positive} | 👎 ${entry.sentiment.negative} | 😐 ${entry.sentiment.neutral})`);
  });
}

// Show prompt enhancement based on feedback
async function showEnhancedPrompt(
  issueContext: IssueContext,
  basePrompt: string
): Promise<string> {
  console.log(chalk.blue('\n🧠 Prompt Enhancement'));
  
  // Generate enhancement context
  console.log('Generating prompt enhancement context based on feedback history...');
  const enhancementContext = await promptEnhancer.generateEnhancementContext(issueContext);
  
  // Show stats about the enhancement context
  console.log(chalk.cyan('\nEnhancement Context:'));
  console.log(`Relevant Feedback Items: ${enhancementContext.relevantFeedback.length}`);
  console.log(`Positive Patterns: ${enhancementContext.patterns.positive.length}`);
  console.log(`Negative Patterns: ${enhancementContext.patterns.negative.length}`);
  console.log(`Similar Solutions: ${enhancementContext.similarSolutions.length}`);
  
  // Show patterns extracted
  if (enhancementContext.patterns.positive.length > 0) {
    console.log(chalk.green('\nPositive Patterns:'));
    enhancementContext.patterns.positive.forEach(pattern => {
      console.log(`👍 ${pattern}`);
    });
  }
  
  if (enhancementContext.patterns.negative.length > 0) {
    console.log(chalk.red('\nNegative Patterns:'));
    enhancementContext.patterns.negative.forEach(pattern => {
      console.log(`👎 ${pattern}`);
    });
  }
  
  // Enhance the prompt
  const enhancedPrompt = promptEnhancer.enhancePrompt(basePrompt, enhancementContext);
  
  // Ask if user wants to see the full enhanced prompt
  const showPrompt = await new Promise<boolean>((resolve) => {
    rl.question(chalk.yellow('\nShow the full enhanced prompt? [y/N]: '), (answer) => {
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
  
  if (showPrompt) {
    console.log(chalk.cyan('\nBase Prompt:'));
    console.log(basePrompt);
    
    console.log(chalk.cyan('\nEnhanced Prompt:'));
    console.log(enhancedPrompt);
  }
  
  return enhancedPrompt;
}

// Main demo function
async function runDemo() {
  console.log(chalk.blue('=== RSOLV Demo Environment ==='));
  console.log('This demo allows you to manually exercise all components of the RSOLV system.');
  
  // Initialize demo
  const initialized = await initializeDemo();
  if (!initialized) {
    console.log(chalk.red('Demo initialization failed. Exiting.'));
    process.exit(1);
  }
  
  // Check for previous demo state
  const previousState = loadDemoState();
  let issueContext: IssueContext | null = null;
  let analysis: IssueAnalysis | null = null;
  let prNumber: string | null = null;
  
  if (previousState) {
    const resumePrevious = await new Promise<boolean>((resolve) => {
      rl.question(
        chalk.yellow('Previous demo session found. Resume? [y/N]: '),
        (answer) => {
          resolve(answer.trim().toLowerCase() === 'y');
        }
      );
    });
    
    if (resumePrevious) {
      issueContext = previousState.issueContext;
      analysis = previousState.analysis;
      prNumber = previousState.prNumber;
      
      console.log(chalk.green('Previous session restored.'));
      if (issueContext) {
        console.log(chalk.cyan('Issue:'), issueContext.title);
      }
      if (prNumber) {
        console.log(chalk.cyan('PR Number:'), prNumber);
      }
    }
  }
  
  // Main demo loop
  let running = true;
  while (running) {
    // Available actions based on current state
    const options = [
      'Get Issue (GitHub or Manual)',
      'Analyze Issue',
      'Generate Solution',
      'Create PR',
      'Simulate Feedback',
      'View Feedback Statistics',
      'Test Prompt Enhancement',
      'Exit Demo'
    ];
    
    // Filter options based on state
    const availableOptions = options.filter((_, index) => {
      if (index === 0) return true; // Always show "Get Issue"
      if (index === 4) return prNumber !== null; // Show "Simulate Feedback" only if PR exists
      if (index === 5) return true; // Always show "View Feedback Statistics"
      if (index === 6) return issueContext !== null; // Show "Test Prompt Enhancement" if issue exists
      if (index === 7) return true; // Always show "Exit Demo"
      if (index === 1) return issueContext !== null; // Show "Analyze Issue" if issue exists
      if (index === 2) return analysis !== null; // Show "Generate Solution" if analysis exists
      if (index === 3) return analysis !== null; // Show "Create PR" if analysis exists
      return false;
    });
    
    const choice = await showMenu(availableOptions);
    const selectedOption = availableOptions[choice - 1];
    
    // Handle selected action
    switch (selectedOption) {
      case 'Get Issue (GitHub or Manual)':
        try {
          issueContext = await getIssueContext();
          console.log(chalk.green('\n✅ Issue context created:'));
          console.log('ID:', chalk.cyan(issueContext.id));
          console.log('Title:', chalk.cyan(issueContext.title));
          console.log('Repository:', chalk.cyan(`${issueContext.repository.owner}/${issueContext.repository.repo}`));
          
          // Save state
          saveDemoState({ issueContext, analysis, prNumber });
        } catch (error) {
          console.error(chalk.red('Error getting issue:'), error);
        }
        break;
        
      case 'Analyze Issue':
        if (!issueContext) {
          console.log(chalk.red('No issue context available. Please get an issue first.'));
          break;
        }
        
        try {
          // Get AI config
          const aiConfig = await getAIConfig();
          
          console.log(chalk.blue('\n🔍 Analyzing issue...'));
          analysis = await analyzeIssue(issueContext, aiConfig);
          
          console.log(chalk.green('\n✅ Issue analysis complete:'));
          console.log('Complexity:', chalk.cyan(analysis.complexity));
          console.log('Estimated Time:', chalk.cyan(`${analysis.estimatedTime} minutes`));
          console.log('Suggested Approach:', chalk.cyan(analysis.approach));
          
          if (analysis.relatedFiles && analysis.relatedFiles.length > 0) {
            console.log('Related Files:');
            analysis.relatedFiles.forEach(file => {
              console.log(chalk.cyan(`- ${file}`));
            });
          }
          
          // Save state
          saveDemoState({ issueContext, analysis, prNumber });
        } catch (error) {
          console.error(chalk.red('Error analyzing issue:'), error);
        }
        break;
        
      case 'Generate Solution':
        if (!issueContext || !analysis) {
          console.log(chalk.red('Issue context or analysis not available. Please complete those steps first.'));
          break;
        }
        
        try {
          // Get AI config
          const aiConfig = await getAIConfig();
          
          console.log(chalk.blue('\n🧠 Generating solution...'));
          
          // Ask whether to use feedback-enhanced prompts
          const useFeedback = await new Promise<boolean>((resolve) => {
            rl.question(
              chalk.yellow('Use feedback-enhanced prompts? [y/N]: '),
              (answer) => {
                resolve(answer.trim().toLowerCase() === 'y');
              }
            );
          });
          
          let solution;
          if (useFeedback) {
            // Create a mock base prompt
            const basePrompt = `Generate a solution for the following issue:
Title: ${issueContext.title}
Description: ${issueContext.body}

The solution should include:
1. Code changes
2. Tests
3. Description of the approach`;
            
            // Enhance the prompt
            const enhancedPrompt = await showEnhancedPrompt(issueContext, basePrompt);
            
            // Use regular solution generation (in a real implementation, we'd use the enhanced prompt)
            solution = await generateSolution(issueContext, analysis, aiConfig);
          } else {
            solution = await generateSolution(issueContext, analysis, aiConfig);
          }
          
          console.log(chalk.green('\n✅ Solution generated:'));
          console.log('Title:', chalk.cyan(solution.title));
          console.log('Description:', chalk.cyan(solution.description));
          
          console.log('\nFiles to modify:');
          solution.files.forEach((file, index) => {
            console.log(chalk.cyan(`${index + 1}. ${file.path}`));
          });
          
          if (solution.tests && solution.tests.length > 0) {
            console.log('\nTests:');
            solution.tests.forEach(test => {
              console.log(chalk.cyan(`- ${test}`));
            });
          }
          
          // Offer to create PR with the solution
          const createPr = await new Promise<boolean>((resolve) => {
            rl.question(
              chalk.yellow('\nCreate PR with this solution? [y/N]: '),
              (answer) => {
                resolve(answer.trim().toLowerCase() === 'y');
              }
            );
          });
          
          if (createPr) {
            // Get GitHub token
            const token = await getGitHubToken();
            
            // Create PR manager
            const prManager = new GitHubPRManager(
              token,
              issueContext.repository.owner,
              issueContext.repository.repo
            );
            
            console.log(chalk.blue('\n🔄 Creating pull request...'));
            try {
              const { prNumber: newPrNumber, prUrl } = await prManager.createPullRequestFromSolution(
                issueContext,
                solution
              );
              
              prNumber = newPrNumber.toString();
              
              console.log(chalk.green('\n✅ Pull request created:'));
              console.log('PR Number:', chalk.cyan(prNumber));
              console.log('PR URL:', chalk.cyan(prUrl));
              
              // Save state
              saveDemoState({ issueContext, analysis, prNumber });
            } catch (error) {
              if (
                error instanceof Error && 
                error.message.includes('Reference already exists')
              ) {
                console.log(chalk.yellow('\n⚠️ This is a demo environment without actual GitHub access.'));
                console.log('Generating a mock PR number for demonstration purposes.');
                
                // Generate a mock PR number for the demo
                prNumber = `demo-${Date.now()}`;
                console.log('Mock PR Number:', chalk.cyan(prNumber));
                
                // Save state
                saveDemoState({ issueContext, analysis, prNumber });
              } else {
                console.error(chalk.red('Error creating PR:'), error);
              }
            }
          }
        } catch (error) {
          console.error(chalk.red('Error generating solution:'), error);
        }
        break;
        
      case 'Create PR':
        console.log(chalk.yellow('\n⚠️ This functionality is already available in the "Generate Solution" option.'));
        console.log('Please use that option to create a PR with a generated solution.');
        break;
        
      case 'Simulate Feedback':
        if (!prNumber) {
          console.log(chalk.red('No PR available for feedback. Please create a PR first.'));
          break;
        }
        
        if (!issueContext) {
          console.log(chalk.red('No issue context available. Please get an issue first.'));
          break;
        }
        
        try {
          await simulateFeedback(issueContext, prNumber);
        } catch (error) {
          console.error(chalk.red('Error simulating feedback:'), error);
        }
        break;
        
      case 'View Feedback Statistics':
        try {
          await displayFeedbackStats();
        } catch (error) {
          console.error(chalk.red('Error displaying feedback statistics:'), error);
        }
        break;
        
      case 'Test Prompt Enhancement':
        if (!issueContext) {
          console.log(chalk.red('No issue context available. Please get an issue first.'));
          break;
        }
        
        try {
          // Create a mock base prompt
          const basePrompt = `Generate a solution for the following issue:
Title: ${issueContext.title}
Description: ${issueContext.body}

The solution should include:
1. Code changes
2. Tests
3. Description of the approach`;
          
          await showEnhancedPrompt(issueContext, basePrompt);
        } catch (error) {
          console.error(chalk.red('Error testing prompt enhancement:'), error);
        }
        break;
        
      case 'Exit Demo':
        console.log(chalk.blue('\n👋 Thank you for using the RSOLV Demo Environment!'));
        running = false;
        break;
    }
    
    if (running) {
      // Pause before showing the menu again
      await new Promise<void>((resolve) => {
        rl.question(chalk.yellow('\nPress Enter to continue...'), () => {
          resolve();
        });
      });
    }
  }
  
  // Clean up
  rl.close();
}

// Main program definition
program
  .name('demo-environment')
  .description('RSOLV Demo Environment')
  .version('1.0.0');

program
  .command('start')
  .description('Start the RSOLV demo environment')
  .action(async () => {
    await runDemo();
  });

program.parse();

// If no command specified, show help
if (!process.argv.slice(2).length) {
  runDemo();
}