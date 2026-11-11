/**
 * The scanner's outside calls as frames the RFC-150 host serves (3c Task 24),
 * so the scan sandbox holds no token and has no network.
 */
import { FrameReader, writeFrame, type Writer } from './frame.js';
import { PatternAPIClient, type PatternResponse } from '../security/pattern-api-client.js';
import type { PatternSource } from '../security/pattern-source.js';
import type { SecurityPattern, VulnerabilityType } from '../security/types.js';
import type { ScanPlatform } from '../scanner/scan-orchestrator.js';
import type { ValidationRequest, ValidationResponse } from '../scanner/ast-validator.js';
import type { SeverityTierMap } from '../scanner/finding-prioritizer.js';
import type { ScanPlanRequest, ScanPlanResponse } from '../scanner/types.js';
import type { ForgeAdapter, ForgeIssue, IssueCreateParams } from '../forge/forge-adapter.js';

const SCANNER_LANGUAGES = ['javascript', 'typescript', 'python', 'ruby', 'java', 'php', 'elixir'];

/** A refusal from the host: `{"error": message}`. */
export class HostError extends Error {}

/** One call at a time: a `{call, args}` frame out, then its answer in. */
export class HostChannel {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly reader: FrameReader, private readonly writer: Writer) {}

  call(name: string, args: Record<string, unknown>): Promise<unknown> {
    const answer = this.queue.then(async () => {
      writeFrame(this.writer, { call: name, args });
      const reply = (await this.reader.next()) as { ok?: unknown; error?: unknown } | null;
      if (reply && 'ok' in reply) return reply.ok;
      throw new HostError(typeof reply?.error === 'string' ? reply.error : 'malformed host answer');
    });
    this.queue = answer.catch(() => undefined);
    return answer;
  }
}

export class FramePatternSource implements PatternSource {
  private readonly cache = new Map<string, Promise<SecurityPattern[]>>();
  private readonly mapper = new PatternAPIClient();

  constructor(private readonly channel: HostChannel) {}

  getPatternsByLanguage(language: string): Promise<SecurityPattern[]> {
    const key = language.toLowerCase();
    let patterns = this.cache.get(key);
    if (!patterns) {
      patterns = this.channel
        .call('patterns', { language: key })
        .then((ok) => (ok as PatternResponse).patterns.map((p) => this.mapper.convertToSecurityPattern(p)));
      this.cache.set(key, patterns);
    }
    return patterns;
  }

  async getPatternsByType(type: VulnerabilityType): Promise<SecurityPattern[]> {
    return (await this.getAllPatterns()).filter((p) => p.type === type);
  }

  async getAllPatterns(): Promise<SecurityPattern[]> {
    const all = await Promise.all(SCANNER_LANGUAGES.map((l) => this.getPatternsByLanguage(l)));
    return all.flat();
  }
}

export class FrameScanPlatform implements ScanPlatform {
  constructor(private readonly channel: HostChannel, private readonly repository: string) {}

  async severityTiers(): Promise<SeverityTierMap> {
    return ((await this.channel.call('severity_tiers', {})) as { tiers: SeverityTierMap }).tiers;
  }

  async plan(request: ScanPlanRequest): Promise<ScanPlanResponse | null> {
    return (await this.channel.call('plan', { body: request })) as ScanPlanResponse;
  }

  async validateVulnerabilities(request: ValidationRequest): Promise<ValidationResponse> {
    const body = { ...request, repository: this.repository };
    return (await this.channel.call('validate', { body })) as ValidationResponse;
  }
}

function unavailable(): Promise<never> {
  return Promise.reject(new Error('not available in the sandbox scan'));
}

/** Issue listing and creation only; `posted` keeps what each created issue said. */
export class FrameForgeAdapter implements ForgeAdapter {
  readonly posted = new Map<number, { title: string; body: string }>();

  constructor(private readonly channel: HostChannel) {}

  async listIssues(_owner: string, _repo: string, labels: string): Promise<ForgeIssue[]> {
    const issues = (await this.channel.call('list_issues', { labels: labels.split(',') })) as Array<{
      number: number;
      title: string;
      state: 'open' | 'closed';
      html_url: string;
      labels: string[];
    }>;
    return issues.map((i) => ({ number: i.number, title: i.title, url: i.html_url, labels: i.labels, state: i.state }));
  }

  async createIssue(_owner: string, _repo: string, params: IssueCreateParams): Promise<ForgeIssue> {
    const { title, body, labels } = params;
    const created = (await this.channel.call('create_issue', { title, body, labels })) as { number: number; html_url: string };
    this.posted.set(created.number, { title, body });
    return { number: created.number, title, url: created.html_url, labels, state: 'open' };
  }

  updateIssue = unavailable;
  addLabels = unavailable;
  removeLabel = unavailable;
  createComment = unavailable;
  createPullRequest = unavailable;
  listPullRequests = unavailable;
  getFileTree = unavailable;
  getFileContent = unavailable;
}
