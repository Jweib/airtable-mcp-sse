import { describe, expect, test } from 'vitest';
import { decodeCursor, encodeCursor } from './cursor.js';

describe('cursor helpers', () => {
  test('encodeCursor returns same offset (pass-through)', () => {
    expect(encodeCursor('itrABC/rec123')).toBe('itrABC/rec123');
  });

  test('decodeCursor returns same cursor (pass-through)', () => {
    expect(decodeCursor('itrABC/rec123')).toBe('itrABC/rec123');
  });

  test('encode/decode keep undefined', () => {
    expect(encodeCursor(undefined)).toBeUndefined();
    expect(decodeCursor(undefined)).toBeUndefined();
  });
});
