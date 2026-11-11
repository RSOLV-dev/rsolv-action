import { PassThrough } from 'stream';
import { FrameReader, writeFrame } from '../frame.js';

export type Answer = { ok: unknown } | { error: string };
export type HostTable = Record<string, (args: Record<string, unknown>) => Answer>;
export interface Received {
  call: string;
  args: Record<string, unknown>;
}

/**
 * An in-memory RFC-150 host: answers the sandbox's `{call, args}` frames from
 * `table`, records them, and stops at `done` (which it doesn't answer).
 */
export function fakeHost(table: HostTable) {
  const toSandbox = new PassThrough();
  const fromSandbox = new PassThrough();
  const received: Received[] = [];
  const hostReader = new FrameReader(fromSandbox);

  const served = (async (): Promise<Received | null> => {
    for (;;) {
      let frame: Received;
      try {
        frame = (await hostReader.next()) as Received;
      } catch {
        return null;
      }
      received.push(frame);
      if (frame.call === 'done') return frame;
      const handler = table[frame.call];
      writeFrame(toSandbox, handler ? handler(frame.args ?? {}) : { error: 'unknown call' });
    }
  })();

  return {
    toSandbox,
    reader: new FrameReader(toSandbox),
    writer: fromSandbox,
    received,
    /** Sends a frame to the sandbox, as the host's config frame. */
    send: (value: unknown) => writeFrame(toSandbox, value),
    /** The `done` frame, or null if the sandbox ended without one. */
    done: async (): Promise<Received | null> => {
      fromSandbox.end();
      return served;
    },
    served,
  };
}
