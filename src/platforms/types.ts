/**
 * Unified issue model for cross-platform support
 */
export interface UnifiedIssue {
  id: string;
  platform: 'github' | 'jira' | 'linear' | 'gitlab';
  key?: string; // Platform-specific key (e.g., PROJ-123 for Jira)
  title: string;
  description: string;
  labels: string[];
  status: string;
  url: string;
  createdAt: Date;
  updatedAt: Date;
  assignee?: {
    id: string;
    name: string;
    email?: string;
  };
  reporter?: {
    id: string;
    name: string;
    email?: string;
  };
  repository?: {
    owner: string;
    name: string;
    url: string;
  };
  customFields?: Record<string, any>;
}

/**
 * Platform adapter interface
 */
export interface PlatformAdapter {
  /**
   * Authenticate with the platform
   */
  authenticate(): Promise<void>;

  /**
   * Search for issues matching criteria
   * @param query Platform-specific query (e.g., JQL for Jira)
   */
  searchIssues(query: string): Promise<UnifiedIssue[]>;

  /**
   * Get a single issue by ID
   */
  getIssue(id: string): Promise<UnifiedIssue>;

  /**
   * Add a comment to an issue
   */
  addComment(issueId: string, comment: string): Promise<void>;

  /**
   * Update issue status
   */
  updateStatus(issueId: string, status: string): Promise<void>;

  /**
   * Link an external URL (like a PR) to an issue
   */
  linkExternalResource(issueId: string, url: string, title: string): Promise<void>;
}

/**
 * Platform configuration
 */
export interface PlatformConfig {
  jira?: {
    host: string; // e.g., 'your-domain.atlassian.net'
    email: string;
    apiToken: string;
    autofixLabel?: string; // Default: 'autofix'
    rsolvLabel?: string; // Default: 'rsolv'
  };
  linear?: {
    apiKey: string;
    autofixLabel?: string;
    rsolvLabel?: string;
  };
  gitlab?: {
    host?: string; // Default: 'gitlab.com'
    token: string;
    autofixLabel?: string;
    rsolvLabel?: string;
  };
}