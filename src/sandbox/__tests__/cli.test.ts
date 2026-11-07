import { describe, it, expect, vi } from 'vitest';
import { PassThrough } from 'stream';

vi.mock('../tool.js', () => ({
  runTool: async (request: { input: { say?: string } }) => {
    console.log(`noise: ${request.input.say ?? ''}`);
    process.stdout.write('raw noise\n');
    return { content: 'result' };
  },
}));

import { main } from '../cli.js';

function collect(stream: PassThrough): () => string {
  const chunks: Buffer[] = [];
  stream.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
  return () => Buffer.concat(chunks).toString('utf-8');
}

function frame(value: unknown): string {
  const body = JSON.stringify(value);
  return `${Buffer.byteLength(body)}\n${body}`;
}

async function run(argv: string[], input: string) {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const out = collect(stdout);
  const err = collect(stderr);
  stdin.end(input);
  const code = await main(argv, stdin, stdout, stderr);
  return { code, stdout: out(), stderr: err() };
}

describe('rsolv-sandbox main', () => {
  it('tool writes exactly one JSON line to stdout', async () => {
    const { code, stdout } = await run(['tool'], frame({ tool: 'read_file', input: { say: 'hi' } }));

    expect(code).toBe(0);
    expect(stdout.split('\n')).toEqual([JSON.stringify({ content: 'result' }), '']);
    expect(JSON.parse(stdout)).toEqual({ content: 'result' });
  });

  it('sends console.log and stray stdout writes during dispatch to stderr', async () => {
    const { stderr } = await run(['tool'], frame({ tool: 'read_file', input: { say: 'hi' } }));

    expect(stderr).toContain('noise: hi');
    expect(stderr).toContain('raw noise');
  });

  it('restores console.log and process.stdout.write afterwards', async () => {
    const log = console.log;
    const write = process.stdout.write;

    await run(['tool'], frame({ tool: 'read_file', input: {} }));

    expect(console.log).toBe(log);
    expect(process.stdout.write).toBe(write);
  });

  it('answers a malformed frame with one JSON error line and exit 1', async () => {
    const { code, stdout } = await run(['tool'], 'x\n');

    expect(code).toBe(1);
    expect(JSON.parse(stdout)).toEqual({ error: 'bad frame' });
  });

  it('patch refuses an invalid base_sha with one JSON line and exit 1', async () => {
    const { code, stdout } = await run(['patch'], frame({ base_sha: 'nope' }));

    expect(code).toBe(1);
    expect(JSON.parse(stdout)).toEqual({ error: 'invalid base_sha' });
  });

  it.each([[[]], [['nope']], [['maintenance']], [['toString']]])('exits 2 for %j', async (argv) => {
    const { code, stdout } = await run(argv, '0\n');

    expect(code).toBe(2);
    expect(stdout).toBe('');
  });
});
