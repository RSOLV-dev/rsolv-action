import { FrameReader, writeFrame, type Writer } from './frame.js';
import { HostChannel, FramePatternSource, FrameScanPlatform, FrameForgeAdapter } from './frame-clients.js';
import { ScanOrchestrator } from '../scanner/scan-orchestrator.js';
import { LocalFileSource } from '../scanner/local-file-source.js';
import { REQUIRED_LABELS } from '../github/label-manager.js';
import { logger } from '../utils/logger.js';

// The platform refuses a registration with more (3c Task 14).
const MAX_FILES_SCANNED = 20_000;
// The host refuses any other label (rsolv-host ScanRelay.allowed_label?/1).
const TRIGGER_LABELS = ['rsolv:validate', 'rsolv:automate'];

interface ScanFrameConfig {
  repository: string;
  max_issues: number;
  issue_label: string;
}

function config(frame: unknown): ScanFrameConfig {
  const c = (frame ?? {}) as Partial<ScanFrameConfig>;
  if (
    typeof c.repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(c.repository) ||
    !Number.isInteger(c.max_issues) || (c.max_issues as number) < 1 || (c.max_issues as number) > 50 ||
    typeof c.issue_label !== 'string'
  ) {
    throw new Error('bad config');
  }
  return c as ScanFrameConfig;
}

/**
 * `rsolv-sandbox scan` (ADR-077 §4): scans the checkout in `cwd` and files
 * issues, every outside call a frame the host serves, then ends with `done`.
 */
export async function runScan(reader: FrameReader, writer: Writer, cwd: string): Promise<void> {
  const { repository, max_issues: maxIssues, issue_label: issueLabel } = config(await reader.next());
  const channel = new HostChannel(reader, writer);

  const labels = REQUIRED_LABELS.filter((l) => !TRIGGER_LABELS.includes(l.name)).map((l) => ({ ...l, color: l.color.toLowerCase() }));
  await channel.call('ensure_labels', { labels }).catch((error: Error) => logger.warn(`Labels not ensured: ${error.message}`));

  const forge = new FrameForgeAdapter(channel);
  const [owner, name] = repository.split('/');
  const result = await new ScanOrchestrator({
    forge,
    platform: new FrameScanPlatform(channel, repository),
    patterns: new FramePatternSource(channel),
    files: new LocalFileSource(cwd),
  }).performScan({
    repository: { owner, name, defaultBranch: 'HEAD' },
    createIssues: true,
    issueLabel,
    maxIssues,
    enableASTValidation: true,
  });

  const findings = new Map(result.vulnerabilities.map((v) => [`${v.cweId}:${v.filePath}:${v.line}`, v]));
  const issues = result.createdIssues.map((issue) => {
    const finding = findings.get(`${issue.cweId}:${issue.filePath}:${issue.line}`);
    return {
      number: issue.number,
      cwe_id: issue.cweId && /^CWE-\d{1,5}$/.test(issue.cweId) ? issue.cweId : undefined,
      ...forge.posted.get(issue.number),
      vulnerability: finding && {
        type: finding.type,
        description: finding.description,
        source: finding.filePath,
        line: finding.line,
      },
    };
  });

  writeFrame(writer, {
    call: 'done',
    args: {
      issues,
      manifest_files: result.manifestFiles ?? {},
      files_scanned: (result.fileList ?? []).slice(0, MAX_FILES_SCANNED),
    },
  });
}
