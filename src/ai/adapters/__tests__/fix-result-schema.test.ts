import { describe, it, expect } from 'vitest';
import { FixResultSchema } from '../claude-agent-sdk';

describe('FixResultSchema', () => {
  it('includes fix_summary property', () => {
    expect(FixResultSchema.properties).toHaveProperty('fix_summary');
    expect(FixResultSchema.properties.fix_summary.type).toBe('string');
  });

  it('includes changes_explanation property', () => {
    expect(FixResultSchema.properties).toHaveProperty('changes_explanation');
    expect(FixResultSchema.properties.changes_explanation.type).toBe('string');
  });

  it('includes risk_assessment property', () => {
    expect(FixResultSchema.properties).toHaveProperty('risk_assessment');
    expect(FixResultSchema.properties.risk_assessment.type).toBe('string');
  });

  it('content fields are not required', () => {
    expect(FixResultSchema.required).not.toContain('fix_summary');
    expect(FixResultSchema.required).not.toContain('changes_explanation');
    expect(FixResultSchema.required).not.toContain('risk_assessment');
  });
});
