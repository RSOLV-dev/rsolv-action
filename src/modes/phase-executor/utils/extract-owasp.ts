/**
 * Extract OWASP category from issue body.
 *
 * Looks for patterns like:
 *   **OWASP:** [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
 *   **OWASP:** A01:2021 - Broken Access Control
 *
 * Returns the category text (e.g., "A03:2021 - Injection") or undefined.
 */
export function extractOwaspFromIssue(body: string | undefined | null): string | undefined {
  if (!body) return undefined;

  // Try markdown link first: **OWASP:** [Category text](url)
  const linkMatch = body.match(/\*\*OWASP:\*\*\s*\[([^\]]+)\]/);
  if (linkMatch) return linkMatch[1];

  // Fall back to plain text: **OWASP:** Category text
  const plainMatch = body.match(/\*\*OWASP:\*\*\s*(.+)/);
  if (plainMatch) return plainMatch[1].trim();

  return undefined;
}
