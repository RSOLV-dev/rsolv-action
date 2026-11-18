/**
 * Makes platform- or model-supplied text inert inside one line of GitHub markdown.
 *
 * Ports the inline rules of the platform's Rsolv.Phases.PrBodyBuilder.inert/2.
 * Newlines become spaces, so the block rules (headings, task lists, setext,
 * fences, link definitions) have no line start to act on. Links and images
 * keep their text and lose their destination. Raw HTML, bare URLs (`://`,
 * `www.`), references (`@user`, `#1`, `GH-1`, `o/r/issues/1`), closing
 * keywords and entities are broken with a zero-width space, so the text links
 * nowhere, pings no one, cross-references no issue and closes none. A
 * fullwidth `＠` passes through: GitHub does not read it as a mention.
 */
const ZWSP = '​';
// ponytail: single-level brackets and parentheses; anything else is left to ACTIVE.
const LINK = /!?\[([^[\]\n]*)\]\([^()\n]*\)/g;
const ACTIVE = /<(?=\S)|\](?=[([:])/g;
const AUTOLINK = /:(?=\/\/)|www(?=\.)/gi;
// `/` before a digit: GitHub reads o/r/issues/1 (and pull/, discussions/) as a reference.
const REFERENCE = /@(?=[A-Za-z0-9-])|#(?=\d)|\bGH-(?=\d)|\/(?=\d)/gi;
const KEYWORD = /\bc(?=lose[sd]?\b)|\bf(?=ix(?:es|ed)?\b)|\br(?=esolve[sd]?\b)/gi;
const ENTITY = /&(?=[#A-Za-z])/g;

export function inertInline(text: string, max: number): string {
  const line = text.replace(/\r\n?|\n/g, ' ');
  const clipped = line.length > max ? `${line.slice(0, max)}…` : line;
  return clipped
    .replace(LINK, '$1')
    .replace(ACTIVE, `$&${ZWSP}`)
    .replace(AUTOLINK, `$&${ZWSP}`)
    .replace(REFERENCE, `$&${ZWSP}`)
    .replace(KEYWORD, `$&${ZWSP}`)
    .replace(ENTITY, `$&${ZWSP}`);
}
