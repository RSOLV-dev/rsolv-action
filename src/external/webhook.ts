import { ExternalWebhookPayload, IssueContext } from '../types';
import { logger } from '../utils/logger';
import { validateApiKey } from '../utils/security';
import * as nodemailer from 'nodemailer';

/**
 * Process an external webhook payload
 */
export async function processWebhookPayload(payload: ExternalWebhookPayload): Promise<IssueContext | null> {
  try {
    // Validate the API key
    const isValidApiKey = await validateApiKey(payload.apiKey);
    if (!isValidApiKey) {
      logger.error('Invalid API key in webhook payload');
      return null;
    }

    // Validate required fields
    if (!payload.source || !payload.issue || !payload.repository) {
      logger.error('Missing required fields in webhook payload');
      return null;
    }

    // Convert to internal issue context format
    const issueContext: IssueContext = {
      id: payload.issue.id,
      source: payload.source as any, // We'll validate this below
      title: payload.issue.title,
      body: payload.issue.description,
      labels: payload.issue.labels || [],
      repository: {
        owner: payload.repository.owner,
        name: payload.repository.name,
        branch: payload.repository.branch,
      },
      metadata: {
        source: payload.source,
        url: payload.issue.url,
      },
      url: payload.issue.url,
    };

    // Validate source
    const validSources = ['jira', 'linear', 'custom'];
    if (!validSources.includes(payload.source)) {
      logger.warning(`Unknown issue source: ${payload.source}. Treating as 'custom'`);
      issueContext.source = 'custom';
    }

    return issueContext;
  } catch (error) {
    logger.error('Error processing webhook payload', error as Error);
    return null;
  }
}

/**
 * Check if a webhook payload is eligible for automation
 */
export function isEligibleForAutomation(issueContext: IssueContext, automationTag: string): boolean {
  // For external sources, we might have different criteria
  // For now, we'll use the same criteria as GitHub issues
  
  // Check if it has the automation tag
  if (!issueContext.labels.includes(automationTag)) {
    return false;
  }
  
  // Check if the issue body is not empty
  if (!issueContext.body || issueContext.body.trim() === '') {
    return false;
  }
  
  // Additional eligibility criteria can be added here
  
  return true;
}

/**
 * Interface for review request data
 */
export interface ExpertReviewRequest {
  prNumber: number;
  prUrl: string;
  repository: {
    owner: string;
    name: string;
  };
  issueTitle: string;
  requestedBy: string;
  customerName?: string;
}

/**
 * Rate limits for expert review requests by customer
 * This would ideally be stored in a database
 */
export const customerRateLimits: Record<string, { 
  dailyLimit: number; 
  monthlyLimit: number; 
  dailyUsed: number;
  monthlyUsed: number;
  lastReset: Date;
}> = {};

/**
 * Check if a customer is rate limited
 */
export function isRateLimited(customerApiKey: string): boolean {
  // If we don't have a record for this customer, they're not rate limited
  if (!customerRateLimits[customerApiKey]) {
    // Default limits: 1 per day, 5 per month
    customerRateLimits[customerApiKey] = {
      dailyLimit: 1,
      monthlyLimit: 5,
      dailyUsed: 0,
      monthlyUsed: 0,
      lastReset: new Date()
    };
    return false;
  }

  const customer = customerRateLimits[customerApiKey];
  const now = new Date();
  
  // Check if we need to reset daily count
  if (now.getDate() !== customer.lastReset.getDate() || 
      now.getMonth() !== customer.lastReset.getMonth() ||
      now.getFullYear() !== customer.lastReset.getFullYear()) {
    customer.dailyUsed = 0;
    customer.lastReset = now;
  }
  
  // Check if we need to reset monthly count
  if (now.getMonth() !== customer.lastReset.getMonth() ||
      now.getFullYear() !== customer.lastReset.getFullYear()) {
    customer.monthlyUsed = 0;
    customer.lastReset = now;
  }
  
  // Check if they've exceeded their limits
  return customer.dailyUsed >= customer.dailyLimit || 
         customer.monthlyUsed >= customer.monthlyLimit;
}

/**
 * Process expert review request webhook
 */
export async function processExpertReviewRequest(request: ExpertReviewRequest, customerApiKey: string): Promise<boolean> {
  try {
    // Validate the API key
    const isValidApiKey = await validateApiKey(customerApiKey);
    if (!isValidApiKey) {
      logger.error('Invalid API key in expert review request');
      return false;
    }
    
    // Check rate limits
    if (isRateLimited(customerApiKey)) {
      logger.error(`Rate limit exceeded for customer with API key ${customerApiKey}`);
      return false;
    }
    
    // Increment usage count
    if (customerRateLimits[customerApiKey]) {
      customerRateLimits[customerApiKey].dailyUsed += 1;
      customerRateLimits[customerApiKey].monthlyUsed += 1;
    }
    
    // Send email notification
    const emailSent = await sendExpertReviewEmail(request);
    
    return emailSent;
  } catch (error) {
    logger.error('Error processing expert review request', error as Error);
    return false;
  }
}

/**
 * Send email notification for expert review
 */
async function sendExpertReviewEmail(request: ExpertReviewRequest): Promise<boolean> {
  try {
    // In production, these would come from environment variables
    // This is a placeholder implementation
    const emailConfig = {
      host: process.env.SMTP_HOST || 'smtp.example.com',
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER || 'user@example.com',
        pass: process.env.SMTP_PASS || 'password'
      },
      from: process.env.NOTIFICATION_FROM || 'notifications@rsolv.dev',
      to: process.env.EXPERT_EMAIL || 'expert@rsolv.dev'
    };

    // In a real implementation, we would use the actual SMTP server
    // For now, we just log the email content
    logger.info(`EXPERT REVIEW REQUEST EMAIL:
From: ${emailConfig.from}
To: ${emailConfig.to}
Subject: Expert Review Requested: PR #${request.prNumber} in ${request.repository.owner}/${request.repository.name}
Body:
Hello RSOLV Expert,

An expert review has been requested for a pull request:

Repository: ${request.repository.owner}/${request.repository.name}
PR Number: ${request.prNumber}
PR URL: ${request.prUrl}
Issue: ${request.issueTitle}
Requested by: ${request.requestedBy}
${request.customerName ? `Customer: ${request.customerName}` : ''}

Please review the PR at your earliest convenience.

Thank you,
RSOLV Team
    `);
    
    // In development or test, we'll skip actual email sending
    if (process.env.NODE_ENV === 'production') {
      // Create transporter
      const transporter = nodemailer.createTransport({
        host: emailConfig.host,
        port: emailConfig.port,
        secure: emailConfig.secure,
        auth: emailConfig.auth
      });
      
      // Send email
      await transporter.sendMail({
        from: emailConfig.from,
        to: emailConfig.to,
        subject: `Expert Review Requested: PR #${request.prNumber} in ${request.repository.owner}/${request.repository.name}`,
        text: `
Hello RSOLV Expert,

An expert review has been requested for a pull request:

Repository: ${request.repository.owner}/${request.repository.name}
PR Number: ${request.prNumber}
PR URL: ${request.prUrl}
Issue: ${request.issueTitle}
Requested by: ${request.requestedBy}
${request.customerName ? `Customer: ${request.customerName}` : ''}

Please review the PR at your earliest convenience.

Thank you,
RSOLV Team
        `,
        html: `
<h2>Expert Review Requested</h2>
<p>An expert review has been requested for a pull request:</p>
<ul>
  <li><strong>Repository:</strong> ${request.repository.owner}/${request.repository.name}</li>
  <li><strong>PR Number:</strong> ${request.prNumber}</li>
  <li><strong>PR URL:</strong> <a href="${request.prUrl}">${request.prUrl}</a></li>
  <li><strong>Issue:</strong> ${request.issueTitle}</li>
  <li><strong>Requested by:</strong> ${request.requestedBy}</li>
  ${request.customerName ? `<li><strong>Customer:</strong> ${request.customerName}</li>` : ''}
</ul>
<p>Please review the PR at your earliest convenience.</p>
<p>Thank you,<br>RSOLV Team</p>
        `
      });
    }
    
    return true;
  } catch (error) {
    logger.error('Error sending expert review email', error as Error);
    return false;
  }
}