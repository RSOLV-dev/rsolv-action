import type { PlatformAdapter, UnifiedIssue } from '../types';

export interface JiraConfig {
  host: string;
  email: string;
  apiToken: string;
  autofixLabel?: string;
  rsolvLabel?: string;
}

export interface JiraIssue {
  id: string;
  key: string;
  fields: {
    summary: string;
    description?: string;
    labels?: string[];
    status: { name: string };
    created: string;
    updated: string;
    assignee?: {
      accountId: string;
      displayName: string;
      emailAddress?: string;
    };
    reporter?: {
      accountId: string;
      displayName: string;
      emailAddress?: string;
    };
  };
}

export class JiraAdapter implements PlatformAdapter {
  private baseUrl: string;
  private authHeader: string;
  private autofixLabel: string;
  private rsolvLabel: string;

  constructor(private config: JiraConfig) {
    this.baseUrl = `https://${config.host}/rest/api/3`;
    this.authHeader = `Basic ${Buffer.from(`${config.email}:${config.apiToken}`).toString('base64')}`;
    this.autofixLabel = config.autofixLabel || 'autofix';
    this.rsolvLabel = config.rsolvLabel || 'rsolv';
  }

  async authenticate(): Promise<void> {
    const response = await fetch(`${this.baseUrl}/myself`, {
      headers: {
        'Authorization': this.authHeader,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to authenticate with Jira: ${response.status} ${response.statusText}`);
    }
  }

  async searchIssues(query: string): Promise<UnifiedIssue[]> {
    const response = await fetch(`${this.baseUrl}/search`, {
      method: 'POST',
      headers: {
        'Authorization': this.authHeader,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        jql: query,
        fields: ['summary', 'description', 'labels', 'status', 'created', 'updated', 'assignee', 'reporter']
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to search Jira issues: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    return data.issues.map((issue: JiraIssue) => this.convertToUnifiedIssue(issue));
  }

  async getIssue(id: string): Promise<UnifiedIssue> {
    const response = await fetch(`${this.baseUrl}/issue/${id}`, {
      headers: {
        'Authorization': this.authHeader,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to get Jira issue: ${response.status} ${response.statusText}`);
    }

    const issue = await response.json();
    return this.convertToUnifiedIssue(issue);
  }

  async addComment(issueId: string, comment: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/issue/${issueId}/comment`, {
      method: 'POST',
      headers: {
        'Authorization': this.authHeader,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        body: {
          type: 'doc',
          version: 1,
          content: [
            {
              type: 'paragraph',
              content: [
                {
                  type: 'text',
                  text: comment
                }
              ]
            }
          ]
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to add comment to Jira issue: ${response.status} ${response.statusText}`);
    }
  }

  async updateStatus(issueId: string, status: string): Promise<void> {
    // First, get available transitions
    const transitionsResponse = await fetch(`${this.baseUrl}/issue/${issueId}/transitions`, {
      headers: {
        'Authorization': this.authHeader,
        'Accept': 'application/json'
      }
    });

    if (!transitionsResponse.ok) {
      throw new Error(`Failed to get transitions: ${transitionsResponse.status} ${transitionsResponse.statusText}`);
    }

    const { transitions } = await transitionsResponse.json();
    const transition = transitions.find((t: any) => t.name === status);

    if (!transition) {
      throw new Error(`Status '${status}' not available for issue ${issueId}`);
    }

    // Update the status
    const response = await fetch(`${this.baseUrl}/issue/${issueId}/transitions`, {
      method: 'POST',
      headers: {
        'Authorization': this.authHeader,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        transition: { id: transition.id }
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to update Jira issue status: ${response.status} ${response.statusText}`);
    }
  }

  async linkExternalResource(issueId: string, url: string, title: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/issue/${issueId}/remotelink`, {
      method: 'POST',
      headers: {
        'Authorization': this.authHeader,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        object: {
          url,
          title,
          icon: {
            url16x16: url.includes('github.com') ? 'https://github.com/favicon.ico' : undefined,
            title: url.includes('github.com') ? 'GitHub Pull Request' : 'External Link'
          }
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Failed to link external resource: ${response.status} ${response.statusText}`);
    }
  }

  private convertToUnifiedIssue(jiraIssue: JiraIssue): UnifiedIssue {
    return {
      id: jiraIssue.id,
      platform: 'jira',
      key: jiraIssue.key,
      title: jiraIssue.fields.summary,
      description: jiraIssue.fields.description || '',
      labels: jiraIssue.fields.labels || [],
      status: jiraIssue.fields.status.name,
      url: `https://${this.config.host}/browse/${jiraIssue.key}`,
      createdAt: new Date(jiraIssue.fields.created),
      updatedAt: new Date(jiraIssue.fields.updated),
      assignee: jiraIssue.fields.assignee ? {
        id: jiraIssue.fields.assignee.accountId,
        name: jiraIssue.fields.assignee.displayName,
        email: jiraIssue.fields.assignee.emailAddress
      } : undefined,
      reporter: jiraIssue.fields.reporter ? {
        id: jiraIssue.fields.reporter.accountId,
        name: jiraIssue.fields.reporter.displayName,
        email: jiraIssue.fields.reporter.emailAddress
      } : undefined
    };
  }

  /**
   * Helper method to search for issues with the autofix label
   */
  async searchAutofixIssues(): Promise<UnifiedIssue[]> {
    return this.searchIssues(`labels = "${this.autofixLabel}"`);
  }

  /**
   * Helper method to search for issues with either autofix or rsolv labels
   */
  async searchRsolvIssues(): Promise<UnifiedIssue[]> {
    // JQL to find issues with either label
    const jql = `labels in ("${this.autofixLabel}", "${this.rsolvLabel}")`;
    return this.searchIssues(jql);
  }
}