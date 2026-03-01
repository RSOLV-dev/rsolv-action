/**
 * RFC-126: HTTP client for PipelineRun lifecycle endpoints.
 *
 * Replaces PhaseDataClient for pipeline-aware storage.
 * The platform handles storage, billing, and state transitions.
 */

export interface PipelineRunIssue {
  issue_number: number;
  cwe_id: string;
  phase: string;
}

export interface CreateRunResult {
  pipeline_run_id: string;
  issues: PipelineRunIssue[];
}

export interface PendingIssue {
  issue_number: number;
  cwe_id: string;
  phase: string;
  pending_action: 'validate' | 'mitigate';
}

export interface PipelineRunClientOptions {
  apiUrl: string;
  apiKey: string;
}

export class PipelineRunClient {
  private apiUrl: string;
  private apiKey: string;

  constructor(options: PipelineRunClientOptions) {
    this.apiUrl = options.apiUrl.replace(/\/$/, '');
    this.apiKey = options.apiKey;
  }

  /**
   * POST /api/v1/pipeline-runs — create a run from scan results.
   */
  async createRun(params: {
    commitSha: string;
    branch?: string;
    mode: string;
    namespace: string;
    createdIssues: Array<{ issue_number: number; cwe_id: string }>;
    vulnerabilities?: unknown[];
    manifestFiles?: Record<string, string>;
  }): Promise<CreateRunResult> {
    const response = await fetch(`${this.apiUrl}/api/v1/pipeline-runs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey,
      },
      body: JSON.stringify({
        commit_sha: params.commitSha,
        branch: params.branch,
        mode: params.mode,
        namespace: params.namespace,
        created_issues: params.createdIssues,
        vulnerabilities: params.vulnerabilities || [],
        manifest_files: params.manifestFiles || {},
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Failed to create pipeline run: ${response.status} ${body}`);
    }

    return response.json();
  }

  /**
   * GET /api/v1/pipeline-runs/:id/pending-issues — get actionable issues.
   */
  async getPendingIssues(pipelineRunId: string): Promise<PendingIssue[]> {
    const response = await fetch(
      `${this.apiUrl}/api/v1/pipeline-runs/${pipelineRunId}/pending-issues`,
      {
        method: 'GET',
        headers: {
          'x-api-key': this.apiKey,
        },
      }
    );

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Failed to get pending issues: ${response.status} ${body}`);
    }

    const data = await response.json();
    return data.pending_issues;
  }

  /**
   * PATCH /api/v1/pipeline-runs/:id/issues/:number — report PR details.
   */
  async reportPR(
    pipelineRunId: string,
    issueNumber: number,
    prUrl: string,
    prNumber: number
  ): Promise<void> {
    const response = await fetch(
      `${this.apiUrl}/api/v1/pipeline-runs/${pipelineRunId}/issues/${issueNumber}`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
        },
        body: JSON.stringify({
          pr_url: prUrl,
          pr_number: prNumber,
        }),
      }
    );

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Failed to report PR: ${response.status} ${body}`);
    }
  }
}
