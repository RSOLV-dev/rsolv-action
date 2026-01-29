// detector-worker.js - Worker thread for running potentially dangerous regex patterns
// Note: This is a .js file because worker threads need a file path, not a module

import { parentPort, workerData } from 'worker_threads';

// Simple console logger for the worker
const logger = {
  info: (msg) => console.log(`[Worker INFO] ${msg}`),
  warn: (msg) => console.warn(`[Worker WARN] ${msg}`),
  error: (msg) => console.error(`[Worker ERROR] ${msg}`)
};

/**
 * Build a set of 1-indexed line numbers that are inside comments.
 * Handles single-line (//) and multi-line block comments.
 */
function buildCommentMap(code) {
  const commentLines = new Set();
  const lines = code.split('\n');
  let inBlockComment = false;

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1; // 1-indexed
    const trimmed = lines[i].trimStart();

    if (inBlockComment) {
      commentLines.add(lineNum);
      if (trimmed.includes('*/')) {
        inBlockComment = false;
      }
      continue;
    }

    // Single-line comment
    if (trimmed.startsWith('//')) {
      commentLines.add(lineNum);
      continue;
    }

    // Block comment start
    if (trimmed.startsWith('/*')) {
      commentLines.add(lineNum);
      const afterOpen = trimmed.substring(2);
      if (!afterOpen.includes('*/')) {
        inBlockComment = true;
      }
      continue;
    }
  }

  return commentLines;
}

/**
 * Run pattern detection in the worker thread
 */
async function runDetection() {
  try {
    const { code, language, patterns, filePath } = workerData;

    logger.info(`Starting detection for ${filePath} with ${patterns.length} patterns`);

    const vulnerabilities = [];
    const lines = code.split('\n');
    const seen = new Set();

    // Build comment map once per file to skip false positives from commented-out code
    const commentLines = buildCommentMap(code);
    if (commentLines.size > 0) {
      logger.info(`Skipping ${commentLines.size} comment lines in ${filePath}`);
    }

    // Process each pattern
    for (const pattern of patterns) {
      if (pattern.patterns?.regex) {
        for (const regex of pattern.patterns.regex) {
          try {
            let match;
            regex.lastIndex = 0; // Reset regex state

            // Critical: This is where the hang happens in the main thread
            // In the worker, it can be terminated forcefully
            while ((match = regex.exec(code)) !== null) {
              const lineNumber = getLineNumber(code, match.index);

              // Skip matches on comment lines
              if (commentLines.has(lineNumber)) {
                if (!regex.global) break;
                continue;
              }

              // Deduplicate by line + type
              const key = `${lineNumber}:${pattern.type}`;
              if (seen.has(key)) {
                if (!regex.global) break;
                continue;
              }
              seen.add(key);

              vulnerabilities.push({
                type: pattern.type,
                severity: pattern.severity,
                line: lineNumber,
                message: `${pattern.name}: ${pattern.description || ''}`,
                description: pattern.description || '',
                confidence: 80, // Default confidence
                cweId: pattern.cweId,
                owaspCategory: pattern.owaspCategory,
                remediation: pattern.remediation,
                filePath: filePath
              });

              // Exit after first match for non-global regex
              if (!regex.global) {
                break;
              }
            }
          } catch (error) {
            logger.error(`Error processing pattern ${pattern.id}: ${error.message}`);
            // Continue with next pattern
          }
        }
      }
    }

    logger.info(`Detection complete: found ${vulnerabilities.length} vulnerabilities`);

    // Send results back to main thread
    parentPort.postMessage({
      type: 'result',
      data: vulnerabilities
    });

  } catch (error) {
    logger.error(`Worker error: ${error.message}`);
    parentPort.postMessage({
      type: 'error',
      error: error.message
    });
  }
}

/**
 * Get line number from character index
 */
function getLineNumber(code, index) {
  const lines = code.substring(0, index).split('\n');
  return lines.length;
}

// Start detection when worker starts
runDetection();