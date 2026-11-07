/**
 * Length-prefixed JSON framing between the host and `rsolv-sandbox` (RFC-150
 * 3c "Sandbox CLI contract"): one line holding the decimal byte length, `\n`,
 * then exactly that many bytes of UTF-8 JSON. `0\n` is the empty frame.
 */

export const MAX_FRAME_BYTES = 16 * 1024 * 1024;

const MAX_HEADER_BYTES = 10;

export class FrameReader {
  private buffer: Buffer = Buffer.alloc(0);
  private ended = false;
  private waiters: Array<() => void> = [];

  constructor(stream: NodeJS.ReadableStream, private readonly maxBytes: number = MAX_FRAME_BYTES) {
    stream.on('data', (chunk: Buffer | string) => {
      this.buffer = Buffer.concat([this.buffer, Buffer.from(chunk)]);
      this.wake();
    });
    stream.on('end', () => {
      this.ended = true;
      this.wake();
    });
  }

  private wake(): void {
    this.waiters.splice(0).forEach((resolve) => resolve());
  }

  /** The next frame's JSON value, or null for the empty frame. */
  async next(): Promise<unknown> {
    for (;;) {
      const newline = this.buffer.indexOf(0x0a);
      if (newline < 0 && this.buffer.length > MAX_HEADER_BYTES) throw new Error('bad frame');
      if (newline >= 0) {
        const header = this.buffer.subarray(0, newline).toString('ascii');
        if (!/^\d{1,9}$/.test(header)) throw new Error('bad frame');
        const length = Number(header);
        if (length > this.maxBytes) throw new Error('frame too large');
        if (this.buffer.length >= newline + 1 + length) {
          const body = this.buffer.subarray(newline + 1, newline + 1 + length);
          this.buffer = this.buffer.subarray(newline + 1 + length);
          return length === 0 ? null : parse(body);
        }
      }
      if (this.ended) throw new Error('unexpected end of input');
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
  }
}

function parse(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString('utf8')) as unknown;
  } catch {
    throw new Error('bad frame');
  }
}

export function writeFrame(stream: NodeJS.WritableStream, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  stream.write(Buffer.concat([Buffer.from(`${body.length}\n`), body]));
}
