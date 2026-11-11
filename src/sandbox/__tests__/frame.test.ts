import { describe, it, expect } from 'vitest';
import { PassThrough } from 'stream';
import { FrameReader, writeFrame } from '../frame.js';

function streamOf(...chunks: string[]): PassThrough {
  const stream = new PassThrough();
  for (const chunk of chunks) stream.write(chunk);
  stream.end();
  return stream;
}

describe('FrameReader', () => {
  it('reads one length-prefixed JSON frame', async () => {
    const reader = new FrameReader(streamOf('7\n{"a":1}'));

    await expect(reader.next()).resolves.toEqual({ a: 1 });
  });

  it('reads a frame split across three chunks once', async () => {
    const stream = new PassThrough();
    const reader = new FrameReader(stream);
    const pending = reader.next();

    stream.write('7');
    stream.write('\n{"a"');
    stream.write(':1}');

    await expect(pending).resolves.toEqual({ a: 1 });
  });

  it('reads consecutive frames in order', async () => {
    const reader = new FrameReader(streamOf('7\n{"a":1}7\n{"b":2}'));

    await expect(reader.next()).resolves.toEqual({ a: 1 });
    await expect(reader.next()).resolves.toEqual({ b: 2 });
  });

  it('reads the empty frame "0\\n" as null', async () => {
    const reader = new FrameReader(streamOf('0\n'));

    await expect(reader.next()).resolves.toBeNull();
  });

  it('rejects a length over the cap before buffering the body', async () => {
    const reader = new FrameReader(streamOf('100\n{'), 10);

    await expect(reader.next()).rejects.toThrow('frame too large');
  });

  it('rejects a non-decimal length line', async () => {
    const reader = new FrameReader(streamOf('x\n'));

    await expect(reader.next()).rejects.toThrow('bad frame');
  });

  it('rejects a length line that never ends', async () => {
    const reader = new FrameReader(streamOf('1'.repeat(64)));

    await expect(reader.next()).rejects.toThrow('bad frame');
  });

  it('rejects a body that is not JSON', async () => {
    const reader = new FrameReader(streamOf('3\nabc'));

    await expect(reader.next()).rejects.toThrow('bad frame');
  });

  it('rejects a stream that ends mid-frame', async () => {
    const reader = new FrameReader(streamOf('7\n{"a"'));

    await expect(reader.next()).rejects.toThrow('unexpected end of input');
  });
});

describe('writeFrame', () => {
  it('prefixes the body with its length in bytes, not characters', () => {
    const stream = new PassThrough();

    writeFrame(stream, { s: 'é' });

    expect(stream.read().toString('utf8')).toBe('10\n{"s":"é"}');
  });
});
