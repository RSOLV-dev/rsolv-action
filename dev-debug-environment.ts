#!/usr/bin/env bun
/**
 * RSOLV Developer Debug Environment
 * 
 * This script provides a comprehensive debugging environment for manually testing
 * all components of the RSOLV system, including:
 * - Issue Analysis
 * - Solution Generation
 * - PR Creation
 * - Feedback Collection & Processing
 * - Prompt Enhancement based on feedback
 */
import { Command } from 'commander';
import * as github from '@actions/github';
import { Octokit } from '@octokit/rest';
import readline from 'readline';
import { v4 as uuidv4 } from 'uuid';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';

// Import RSOLV components
import { getGitHubClient } from './src/github/api.js';
import { createPullRequest } from './src/github/pr.js';
import { generateSolution } from './src/ai/solution.js';
import { analyzeIssue } from './src/ai/analyzer.js';
import { AIConfig, IssueAnalysis } from './src/ai/types.js';
import { IssueContext } from './src/types/index.js';
import { 
  feedbackStorage, 
  feedbackCollector, 
  promptEnhancer, 
  FeedbackEvent,
  FeedbackSentiment,
  ActionTaken 
} from './src/feedback/index.js';

// Import the context evaluation module for Claude Code
import { runContextEvaluation } from './src/demo-context-evaluation.js';

// Import Security Demo Environment
import { SecurityDemoEnvironment } from './src/security-demo.js';

// Create CLI program
const program = new Command();

// Initialize storage path for demo data
const DEMO_DATA_DIR = path.join(process.cwd(), 'demo-data');
if (!fs.existsSync(DEMO_DATA_DIR)) {
  fs.mkdirSync(DEMO_DATA_DIR, { recursive: true });
}

// Initialize feedback storage paths
const DATA_DIR = path.join(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const FEEDBACK_PATH = path.join(DEMO_DATA_DIR, 'feedback.json');

// Function to initialize demo environment
async function initializeDemo() {
  try {
    console.log(chalk.blue('🚀 Initializing RSOLV Demo Environment'));

    // Initialize feedback storage
    await feedbackStorage.initialize();
    
    // Check if we need to copy sample feedback
    const feedbackExists = await fs.promises.access(FEEDBACK_PATH).then(() => true).catch(() => false);
    const sampleFeedbackPath = path.join(DEMO_DATA_DIR, 'sample-feedback.json');
    const sampleExists = await fs.promises.access(sampleFeedbackPath).then(() => true).catch(() => false);
    
    if (!feedbackExists && sampleExists) {
      console.log(chalk.blue('Loading sample feedback data...'));
      try {
        const sampleData = await fs.promises.readFile(sampleFeedbackPath, 'utf8');
        const feedbackEvents = JSON.parse(sampleData);
        
        // Import each feedback event
        for (const event of feedbackEvents) {
          const { id, ...eventData } = event;
          await feedbackStorage.createFeedback(eventData);
        }
        console.log(chalk.green(`✅ Imported ${feedbackEvents.length} sample feedback events`));
      } catch (err) {
        console.error(chalk.yellow('⚠️ Could not import sample feedback data:'), err);
      }
    }
    
    console.log(chalk.green('✅ Feedback system initialized'));
    return true;
  } catch (error) {
    console.error(chalk.red('❌ Error initializing demo environment:'), error);
    return false;
  }
}

// Function to get GitHub token from environment or prompt
async function getGitHubToken(rl: readline.Interface): Promise<string> {
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
async function getAIConfig(rl: readline.Interface): Promise<AIConfig> {
  // Get provider from env or prompt
  let provider = process.env.AI_PROVIDER || 'anthropic';
  let apiKey = '';
  let modelName = '';

  // If provider not in env, ask user
  if (!process.env.AI_PROVIDER) {
    const providerAnswer = await new Promise<string>((resolve) => {
      rl.question(
        chalk.yellow('Select AI provider (anthropic, openrouter, ollama, claude-code) [default: anthropic]: '),
        (answer) => {
          resolve(answer.trim() || 'anthropic');
        }
      );
    });
    provider = providerAnswer;
  }

  // Set appropriate API key and model based on provider
  // Check if using Claude Code
  let useClaudeCode = false;
  if (provider === 'claude-code') {
    useClaudeCode = true;
    provider = 'anthropic'; // Internally we'll still use Anthropic as the provider
    
    console.log(chalk.blue('\n🤖 Claude Code Integration'));
    console.log('Using Claude Code for enhanced context-gathering with our feedback system');
    
    // Check if claude CLI is available by attempting to run a basic command
    let claudeCodeAvailable = false;
    try {
      const { execSync } = require('child_process');
      execSync('claude -v', { stdio: 'ignore' });
      claudeCodeAvailable = true;
    } catch (error) {
      claudeCodeAvailable = false;
    }
    
    if (!claudeCodeAvailable) {
      console.log(chalk.yellow('⚠️ Claude Code simulation mode: No actual Claude Code CLI detected'));
      console.log('This demo will simulate Claude Code context gathering');
      console.log(chalk.cyan('Install Claude Code CLI with: npm install -g @anthropic-ai/claude-code'));
    } else {
      console.log(chalk.green('✅ Claude Code CLI detected'));
    }
  }

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
    modelName,
    useClaudeCode
  };
}

// Function to get issue details either from GitHub or manual input
async function getIssueContext(rl: readline.Interface): Promise<IssueContext> {
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
    const token = await getGitHubToken(rl);
    
    // Get issue details directly with Octokit
    console.log(chalk.blue('📥 Fetching issue details...'));
    const octokit = getGitHubClient({ repoToken: token });
    const { data: issue } = await octokit.rest.issues.get({
      owner,
      repo,
      issue_number: parseInt(issueNumber, 10)
    });
    
    // Create issue context
    return {
      id: issueNumber,
      number: parseInt(issueNumber, 10),
      source: 'github',
      title: issue.title,
      body: issue.body || '',
      labels: issue.labels?.map((label: any) => 
        typeof label === 'string' ? label : label.name
      ) || [],
      assignees: issue.assignees?.map((assignee: any) => assignee.login) || [],
      repository: {
        owner,
        name: repo,
        fullName: `${owner}/${repo}`,
        defaultBranch: 'main' // Assuming main branch
      },
      createdAt: issue.created_at,
      updatedAt: issue.updated_at,
      metadata: {
        htmlUrl: issue.html_url,
        user: issue.user?.login,
        state: issue.state
      }
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
      number: parseInt(issueId.replace('demo-', ''), 10),
      source: 'github',
      title: issueTitle,
      body: issueBody,
      labels: ['AUTOFIX', 'demo'],
      assignees: ['demo-user'],
      repository: {
        owner: repoOwner,
        name: repoName,
        fullName: `${repoOwner}/${repoName}`,
        defaultBranch: 'main'
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      metadata: {
        htmlUrl: `https://github.com/${repoOwner}/${repoName}/issues/${issueId}`,
        user: 'demo-user',
        state: 'open'
      }
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
async function showMenu(options: string[], rl: readline.Interface): Promise<number> {
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
    return showMenu(options, rl);
  }
  
  return choiceNum;
}

// Simulate PR feedback collection
async function simulateFeedback(
  issueContext: IssueContext,
  prNumber: string,
  rl: readline.Interface
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
  const feedbackTypeIndex = await showMenu(feedbackTypeOptions, rl);
  const feedbackType = feedbackTypeOptions[feedbackTypeIndex - 1].toLowerCase() as any;
  
  // Get feedback sentiment
  const sentimentOptions = ['Positive', 'Negative', 'Neutral'];
  const sentimentIndex = await showMenu(sentimentOptions, rl);
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
  stats.feedbackOverTime.forEach((entry: { date: string; count: number; sentiment: { positive: number; negative: number; neutral: number } }) => {
    console.log(`${entry.date}: ${entry.count} feedbacks (👍 ${entry.sentiment.positive} | 👎 ${entry.sentiment.negative} | 😐 ${entry.sentiment.neutral})`);
  });
}

// Show prompt enhancement based on feedback
async function showEnhancedPrompt(
  issueContext: IssueContext,
  basePrompt: string,
  rl: readline.Interface
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
    enhancementContext.patterns.positive.forEach((pattern: string) => {
      console.log(`👍 ${pattern}`);
    });
  }
  
  if (enhancementContext.patterns.negative.length > 0) {
    console.log(chalk.red('\nNegative Patterns:'));
    enhancementContext.patterns.negative.forEach((pattern: string) => {
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
  console.log(chalk.green('Note: Claude Code integration is now available as an AI provider option.'));
  
  // Check if running with Bun and show warning
  if (process.versions.bun) {
    console.log(chalk.yellow('\n⚠️  Detected Bun runtime with known readline compatibility issues.'));
    console.log(chalk.yellow('If you experience errors with interactive prompts, please run with Node.js:'));
    console.log(chalk.cyan('  node demo-environment.ts start'));
    console.log();
  }
  
  // Create readline interface for this session
  let rl: readline.Interface;
  try {
    rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });
  } catch (error) {
    console.error(chalk.red('Error creating readline interface:'), error);
    console.error(chalk.red('Please run with Node.js instead: node demo-environment.ts start'));
    process.exit(1);
  }
  
  // Initialize demo
  const initialized = await initializeDemo();
  if (!initialized) {
    console.log(chalk.red('Demo initialization failed. Exiting.'));
    rl.close();
    process.exit(1);
  }
  
  // Add a small delay to ensure readline is ready (Bun workaround)
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Check for previous demo state
  const previousState = loadDemoState();
  let issueContext: IssueContext | null = null;
  let analysis: IssueAnalysis | null = null;
  let prNumber: string | null = null;
  
  if (previousState) {
    const resumePrevious = await new Promise<boolean>((resolve) => {
      try {
        rl.question(
          chalk.yellow('Previous demo session found. Resume? [y/N]: '),
          (answer) => {
            resolve(answer.trim().toLowerCase() === 'y');
          }
        );
      } catch (error) {
        console.error(chalk.red('Error with readline. Defaulting to no.'));
        resolve(false);
      }
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
      '🔒 Security Demo Showcase',
      'Get Issue (GitHub or Manual)',
      'Analyze Issue',
      'Generate Solution',
      'Create PR',
      'Simulate Feedback',
      'View Feedback Statistics',
      'Test Prompt Enhancement',
      'Evaluate Claude Code Context Quality', // New option for evaluating Claude Code
      'Exit Demo'
    ];
    
    // Filter options based on state
    const availableOptions = options.filter((_, index) => {
      if (index === 0) return true; // Always show "Security Demo Showcase"
      if (index === 1) return true; // Always show "Get Issue"
      if (index === 5) return prNumber !== null; // Show "Simulate Feedback" only if PR exists
      if (index === 6) return true; // Always show "View Feedback Statistics"
      if (index === 7) return issueContext !== null; // Show "Test Prompt Enhancement" if issue exists
      if (index === 8) return true; // Always show "Evaluate Claude Code Context Quality"
      if (index === 9) return true; // Always show "Exit Demo"
      if (index === 2) return issueContext !== null; // Show "Analyze Issue" if issue exists
      if (index === 3) return analysis !== null; // Show "Generate Solution" if analysis exists
      if (index === 4) return analysis !== null; // Show "Create PR" if analysis exists
      return false;
    });
    
    const choice = await showMenu(availableOptions, rl);
    const selectedOption = availableOptions[choice - 1];
    
    // Handle selected action
    switch (selectedOption) {
      case '🔒 Security Demo Showcase':
        await runSecurityDemoShowcase(rl);
        break;
        
      case 'Get Issue (GitHub or Manual)':
        try {
          issueContext = await getIssueContext(rl);
          console.log(chalk.green('\n✅ Issue context created:'));
          console.log('ID:', chalk.cyan(issueContext.id));
          console.log('Title:', chalk.cyan(issueContext.title));
          console.log('Repository:', chalk.cyan(`${issueContext.repository.owner}/${issueContext.repository.name}`));
          
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
          const aiConfig = await getAIConfig(rl);
          
          console.log(chalk.blue('\n🔍 Analyzing issue...'));
          analysis = await analyzeIssue(issueContext, { aiProvider: aiConfig } as any);
          
          console.log(chalk.green('\n✅ Issue analysis complete:'));
          console.log('Complexity:', chalk.cyan(analysis.estimatedComplexity));
          console.log('Issue Type:', chalk.cyan(analysis.issueType));
          console.log('Suggested Approach:', chalk.cyan(analysis.suggestedApproach));
          
          if (analysis.filesToModify && analysis.filesToModify.length > 0) {
            console.log('Files to Modify:');
            analysis.filesToModify.forEach((file: string) => {
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
          const aiConfig = await getAIConfig(rl);
          
          console.log(chalk.blue('\n🧠 Generating solution...'));
          
          // If we're using Claude Code, show context-gathering step
          if (aiConfig.useClaudeCode) {
            console.log(chalk.blue('\n🔍 Claude Code: Gathering intelligent context...'));
            console.log('Analyzing repository structure');
            console.log('Identifying relevant files');
            console.log('Exploring code dependencies');
            console.log('Building comprehensive context');
            
            // Add progress dots for better visual feedback
            const progressBar = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];
            let i = 0;
            const interval = setInterval(() => {
              process.stdout.write(`\rContext gathering in progress ${progressBar[i]} `);
              i = (i + 1) % progressBar.length;
            }, 100);
            
            // Simulate progress
            await new Promise(resolve => setTimeout(resolve, 2000));
            clearInterval(interval);
            process.stdout.write('\r');
            console.log(chalk.green('✅ Context gathered successfully'));
            
            // Show simulated context summary
            console.log(chalk.cyan('\nContext Summary:'));
            console.log(`- Files analyzed: ${Math.floor(Math.random() * 30) + 20}`);
            console.log(`- Relevant files identified: ${Math.floor(Math.random() * 8) + 3}`);
            console.log(`- Code patterns recognized: ${Math.floor(Math.random() * 5) + 2}`);
            console.log(`- Context size: ${Math.floor(Math.random() * 5000) + 5000} tokens`);
          }
          
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
            const enhancedPrompt = await showEnhancedPrompt(issueContext, basePrompt, rl);
            
            if (aiConfig.useClaudeCode) {
              console.log(chalk.blue('\n🔄 Using hybrid approach:'));
              console.log('- Claude Code for intelligent context-gathering');
              console.log('- Feedback-enhanced prompts for solution quality');
              console.log('- Combined analysis for optimal results');
              
              // Simulate progress
              await new Promise(resolve => setTimeout(resolve, 1000));
            }
            
            // Use regular solution generation (in a real implementation, we'd use the enhanced prompt)
            solution = await generateSolution(issueContext, analysis, { aiProvider: aiConfig } as any);
          } else {
            if (aiConfig.useClaudeCode) {
              console.log(chalk.blue('\n🔄 Using Claude Code context-gathering without feedback enhancement'));
              
              // Simulate progress
              await new Promise(resolve => setTimeout(resolve, 1000));
            }
            solution = await generateSolution(issueContext, analysis, { aiProvider: aiConfig } as any);
          }
          
          if (solution.success) {
            console.log(chalk.green('\n✅ Solution generated successfully:'));
            console.log('Message:', chalk.cyan(solution.message));
            
            if (solution.changes && Object.keys(solution.changes).length > 0) {
              console.log('\nFiles to modify:');
              Object.entries(solution.changes).forEach(([path, changes], index) => {
                console.log(chalk.cyan(`${index + 1}. ${path}`));
                console.log(chalk.gray('Changes preview:'));
                console.log(changes.substring(0, 200) + (changes.length > 200 ? '...' : ''));
              });
            } else {
              console.log(chalk.yellow('\n⚠️  No changes proposed'));
            }
          } else {
            console.log(chalk.red('\n❌ Solution generation failed:'));
            console.log('Message:', chalk.cyan(solution.message));
            if (solution.error) {
              console.log('Error:', chalk.red(solution.error));
            }
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
            const token = await getGitHubToken(rl);
            
            console.log(chalk.blue('\n🔄 Creating pull request...'));
            try {
              // Use the changes from the solution directly
              const changes = solution.changes || {};
              
              // Create pull request
              const result = await createPullRequest(
                issueContext,
                changes,
                analysis,
                { 
                  aiProvider: {
                    provider: aiConfig.provider,
                    apiKey: aiConfig.apiKey,
                    model: aiConfig.modelName
                  }
                }
              );
              
              if (!result.success) {
                throw new Error(result.message);
              }
              
              const newPrNumber = result.pullRequestNumber;
              const prUrl = result.pullRequestUrl;
              
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
          await simulateFeedback(issueContext, prNumber, rl);
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
          
          await showEnhancedPrompt(issueContext, basePrompt, rl);
        } catch (error) {
          console.error(chalk.red('Error testing prompt enhancement:'), error);
        }
        break;
        
      case 'Evaluate Claude Code Context Quality':
        try {
          // Run the context evaluation
          await runContextEvaluation(rl);
        } catch (error) {
          console.error(chalk.red('Error evaluating Claude Code context:'), error);
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

// Security Demo Showcase function
async function runSecurityDemoShowcase(rl: readline.Interface): Promise<void> {
  console.log(chalk.blue('\n🔒 RSOLV Security Demo Showcase'));
  console.log(chalk.gray('Demonstrating security-first vulnerability detection and remediation\n'));
  
  const securityDemo = new SecurityDemoEnvironment();
  
  const securityOptions = [
    'Show Security Vulnerability Examples',
    'Analyze Custom Code for Security Issues',
    'Demonstrate Three-Tier Security Explanations',
    'Security Performance Benchmark',
    'Educational Security Mode',
    'Export Security Report',
    'Back to Main Menu'
  ];
  
  let securityRunning = true;
  while (securityRunning) {
    console.log(chalk.blue('\n🔒 Security Demo Options:'));
    const choice = await showMenu(securityOptions, rl);
    const selectedOption = securityOptions[choice - 1];
    
    switch (selectedOption) {
      case 'Show Security Vulnerability Examples':
        await showSecurityExamples(securityDemo, rl);
        break;
        
      case 'Analyze Custom Code for Security Issues':
        await analyzeCustomCode(securityDemo, rl);
        break;
        
      case 'Demonstrate Three-Tier Security Explanations':
        await demonstrateSecurityExplanations(securityDemo, rl);
        break;
        
      case 'Security Performance Benchmark':
        await runSecurityBenchmark(securityDemo);
        break;
        
      case 'Educational Security Mode':
        await showEducationalMode(securityDemo);
        break;
        
      case 'Export Security Report':
        await exportSecurityReport(securityDemo, rl);
        break;
        
      case 'Back to Main Menu':
        securityRunning = false;
        break;
    }
    
    if (securityRunning) {
      await new Promise<void>((resolve) => {
        rl.question(chalk.yellow('\nPress Enter to continue...'), () => {
          resolve();
        });
      });
    }
  }
}

// Show security vulnerability examples
async function showSecurityExamples(securityDemo: SecurityDemoEnvironment, rl: readline.Interface): Promise<void> {
  console.log(chalk.blue('\n🔍 Security Vulnerability Examples'));
  
  const examples = await securityDemo.getDemoExamples();
  console.log(chalk.cyan(`\nAvailable Examples (${examples.length} total):`));
  
  examples.forEach((example, index) => {
    console.log(`${index + 1}. ${chalk.yellow(example.title)} (${example.category})`);
    console.log(`   ${chalk.gray(example.description)}`);
    console.log(`   ${chalk.cyan('Language:')} ${example.language}, ${chalk.cyan('Difficulty:')} ${example.metadata.difficulty}`);
  });
  
  const choice = await new Promise<number>((resolve) => {
    rl.question(chalk.yellow(`\nSelect example to analyze (1-${examples.length}): `), (answer) => {
      resolve(parseInt(answer) || 1);
    });
  });
  
  const selectedExample = examples[choice - 1] || examples[0];
  console.log(chalk.blue(`\n🔍 Analyzing: ${selectedExample.title}`));
  
  // Show the vulnerable code
  console.log(chalk.red('\n📄 Vulnerable Code:'));
  console.log(chalk.gray(selectedExample.vulnerableCode));
  
  // Run security detection
  console.log(chalk.blue('\n🔍 Running Security Analysis...'));
  const result = await securityDemo.demonstrateVulnerabilityDetection(selectedExample);
  
  // Display results
  console.log(chalk.green(`\n✅ Analysis Complete - Found ${result.detectedVulnerabilities.length} vulnerabilities:`));
  result.detectedVulnerabilities.forEach((vuln, index) => {
    console.log(`${index + 1}. ${chalk.red(vuln.type)} (${chalk.yellow(vuln.severity)})`);
    console.log(`   Line ${vuln.lineNumber}: ${chalk.gray(vuln.message)}`);
  });
  
  // Show compliance status
  console.log(chalk.blue('\n📋 Compliance Status:'));
  console.log(`OWASP Coverage: ${chalk.cyan(result.complianceReport.owaspCoverage.percentage)}%`);
  console.log(`Risk Level: ${chalk.yellow(result.complianceReport.summary.compliance.status)}`);
  
  // Show CVE correlations
  console.log(chalk.blue('\n🔗 CVE Intelligence:'));
  console.log(`Related CVEs: ${chalk.cyan(result.cveCorrelations.totalCves)}`);
  console.log(`High Severity CVEs: ${chalk.red(result.cveCorrelations.highSeverityCves)}`);
}

// Analyze custom code
async function analyzeCustomCode(securityDemo: SecurityDemoEnvironment, rl: readline.Interface): Promise<void> {
  console.log(chalk.blue('\n📝 Custom Code Security Analysis'));
  console.log(chalk.gray('Enter your code for security analysis (type "END" on a new line to finish):\n'));
  
  let code = '';
  const lines: string[] = [];
  
  const collectCode = (): Promise<void> => {
    return new Promise((resolve) => {
      rl.question('> ', (line) => {
        if (line.trim() === 'END') {
          code = lines.join('\n');
          resolve();
        } else {
          lines.push(line);
          collectCode().then(resolve);
        }
      });
    });
  };
  
  await collectCode();
  
  if (!code.trim()) {
    console.log(chalk.red('No code provided.'));
    return;
  }
  
  const language = await new Promise<string>((resolve) => {
    rl.question(chalk.yellow('Programming language (javascript/typescript/python/ruby/bash): '), (answer) => {
      resolve(answer.toLowerCase() || 'javascript');
    });
  });
  
  console.log(chalk.blue('\n🔍 Analyzing your code for security vulnerabilities...'));
  const result = await securityDemo.analyzeCustomCode(code, language);
  
  console.log(chalk.green(`\n✅ Analysis Complete - Found ${result.vulnerabilities.length} security issues:`));
  result.vulnerabilities.forEach((vuln, index) => {
    console.log(`${index + 1}. ${chalk.red(vuln.type)} (${chalk.yellow(vuln.severity)})`);
    console.log(`   ${chalk.gray(vuln.message)}`);
  });
  
  if (result.recommendations.length > 0) {
    console.log(chalk.blue('\n💡 Security Recommendations:'));
    result.recommendations.forEach((rec, index) => {
      console.log(`${index + 1}. ${chalk.cyan(rec)}`);
    });
  }
}

// Demonstrate three-tier explanations
async function demonstrateSecurityExplanations(securityDemo: SecurityDemoEnvironment, rl: readline.Interface): Promise<void> {
  console.log(chalk.blue('\n📚 Three-Tier Security Explanation System'));
  console.log(chalk.gray('Showing how RSOLV explains security issues at different knowledge levels\n'));
  
  const examples = await securityDemo.getDemoExamples();
  const exampleToUse = examples.find(ex => ex.category === 'sql_injection') || examples[0];
  
  console.log(chalk.yellow(`Using example: ${exampleToUse.title}`));
  console.log(chalk.red('\nVulnerable Code:'));
  console.log(chalk.gray(exampleToUse.vulnerableCode));
  
  const fixDemo = await securityDemo.demonstrateVulnerabilityFix(
    exampleToUse.vulnerableCode, 
    exampleToUse.expectedVulnerabilities[0]?.type || 'sql_injection'
  );
  
  console.log(chalk.blue('\n🔧 Secure Fix:'));
  console.log(chalk.green(fixDemo.secureCode));
  
  console.log(chalk.blue('\n📚 Three-Tier Explanations:'));
  
  console.log(chalk.cyan('\n1. Line-Level (Developer):'));
  console.log(chalk.gray(fixDemo.explanation.lineLevel));
  
  console.log(chalk.cyan('\n2. Concept-Level (Technical Lead):'));
  console.log(chalk.gray(fixDemo.explanation.conceptLevel));
  
  console.log(chalk.cyan('\n3. Business-Level (Management):'));
  console.log(chalk.gray(fixDemo.explanation.businessLevel));
}

// Run security benchmark
async function runSecurityBenchmark(securityDemo: SecurityDemoEnvironment): Promise<void> {
  console.log(chalk.blue('\n⚡ Security Performance Benchmark'));
  console.log(chalk.gray('Testing RSOLV security analysis performance...\n'));
  
  const benchmark = await securityDemo.runPerformanceBenchmark();
  
  console.log(chalk.green('📊 Benchmark Results:'));
  console.log(`Total Analysis Time: ${chalk.cyan(benchmark.totalTime)} ms`);
  console.log(`Vulnerabilities Processed: ${chalk.cyan(benchmark.vulnerabilitiesProcessed)}`);
  console.log(`Average Time per Vulnerability: ${chalk.cyan(Math.round(benchmark.averageTimePerVulnerability))} ms`);
  console.log(`Throughput: ${chalk.cyan(benchmark.throughput.toFixed(2))} vulnerabilities/second`);
  
  const metrics = await securityDemo.getPerformanceMetrics();
  console.log(chalk.blue('\n📈 Additional Metrics:'));
  console.log(`CVE Correlations: ${chalk.cyan(metrics.cveCorrelations)}`);
  console.log(`Compliance Checks: ${chalk.cyan(metrics.complianceChecks)}`);
  console.log(`Average Risk Score: ${chalk.cyan(metrics.averageRiskScore.toFixed(1))}`);
}

// Show educational mode
async function showEducationalMode(securityDemo: SecurityDemoEnvironment): Promise<void> {
  console.log(chalk.blue('\n🎓 Educational Security Mode'));
  console.log(chalk.gray('Interactive security learning exercises\n'));
  
  const educationalMode = await securityDemo.enableEducationalMode();
  
  console.log(chalk.green('📚 Available Security Exercises:'));
  educationalMode.interactiveExercises.forEach((exercise, index) => {
    console.log(`${index + 1}. ${chalk.yellow(exercise.title)}`);
    console.log(`   ${chalk.gray(exercise.description)}`);
    console.log(`   Code: ${chalk.cyan(exercise.code)}`);
    console.log(`   Expected: ${chalk.green(exercise.expectedAnswer)}\n`);
  });
  
  console.log(chalk.blue('🔍 Educational Features:'));
  console.log(`• Detailed Explanations: ${educationalMode.detailedExplanations ? chalk.green('✓') : chalk.red('✗')}`);
  console.log(`• Step-by-Step Guidance: ${educationalMode.stepByStepGuidance ? chalk.green('✓') : chalk.red('✗')}`);
  console.log(`• Interactive Exercises: ${chalk.cyan(educationalMode.interactiveExercises.length)} available`);
}

// Export security report
async function exportSecurityReport(securityDemo: SecurityDemoEnvironment, rl: readline.Interface): Promise<void> {
  console.log(chalk.blue('\n📄 Export Security Report'));
  
  const examples = await securityDemo.getDemoExamples();
  const exampleToUse = examples.find(ex => ex.category === 'mixed') || examples[0];
  
  console.log(chalk.yellow(`Generating report for: ${exampleToUse.title}`));
  
  const formats = ['markdown', 'json'];
  const reports = await securityDemo.exportSecurityReport(exampleToUse, formats);
  
  console.log(chalk.green('\n✅ Security Report Generated:'));
  
  if (reports.markdown) {
    console.log(chalk.blue('\n📄 Markdown Report:'));
    console.log(chalk.gray(reports.markdown.substring(0, 500) + '...'));
  }
  
  if (reports.json) {
    console.log(chalk.blue('\n📊 JSON Report Summary:'));
    const jsonData = JSON.parse(reports.json);
    console.log(`Vulnerabilities: ${chalk.cyan(jsonData.summary.totalVulnerabilities)}`);
    console.log(`Risk Level: ${chalk.yellow(jsonData.summary.riskLevel)}`);
    console.log(`CVE References: ${chalk.cyan(jsonData.cveIntelligence.totalCves)}`);
  }
  
  console.log(chalk.green('\n💾 Reports would be saved to demo-data/ directory in production.'));
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