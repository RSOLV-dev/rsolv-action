import { describe, it, expect, beforeEach, vi, jest, spyOn } from 'vitest';
import { ensureLabelsExist } from '../label-manager.js';

// Mock fetch globally
global.fetch = vi.fn();

describe('Label Manager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create missing labels', async () => {
    const mockFetch = global.fetch as any;
    
    // Mock fetching existing labels (only has 'security')
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [
        { name: 'security', color: 'D93F0B' }
      ]
    });
    
    // Mock creating labels - should be called for each missing label
    const createdLabels: string[] = [];
    mockFetch.mockImplementation(async (url: string, options?: any) => {
      if (options?.method === 'POST') {
        const body = JSON.parse(options.body);
        createdLabels.push(body.name);
        return { ok: true, json: async () => ({ name: body.name }) };
      }
      return { ok: false };
    });
    
    await ensureLabelsExist('test-owner', 'test-repo', 'test-token');
    
    // Should have created all missing labels
    expect(createdLabels).toContain('rsolv:detected');
    expect(createdLabels).toContain('rsolv:validate');
    expect(createdLabels).toContain('rsolv:automate');
    expect(createdLabels).toContain('critical');
    expect(createdLabels).toContain('high');
    expect(createdLabels).toContain('medium');
    expect(createdLabels).toContain('low');
    expect(createdLabels).toContain('automated-scan');
    
    // Should NOT recreate existing label
    expect(createdLabels).not.toContain('security');
  });
  
  it('should handle API errors gracefully', async () => {
    const mockFetch = global.fetch as any;
    
    // Mock API failure
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403
    });
    
    // Should not throw - just log warning
    await expect(async () => {
      await ensureLabelsExist('test-owner', 'test-repo', 'test-token');
    }).not.toThrow();
  });
  
  it('should be case-insensitive when checking existing labels', async () => {
    const mockFetch = global.fetch as any;
    
    // Mock existing labels with different case
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => [
        { name: 'RSOLV:Detected' },  // Different case
        { name: 'Security' }
      ]
    });
    
    const createdLabels: string[] = [];
    mockFetch.mockImplementation(async (url: string, options?: any) => {
      if (options?.method === 'POST') {
        const body = JSON.parse(options.body);
        createdLabels.push(body.name);
        return { ok: true, json: async () => ({ name: body.name }) };
      }
      return { ok: false };
    });
    
    await ensureLabelsExist('test-owner', 'test-repo', 'test-token');
    
    // Should not recreate labels that exist with different case
    expect(createdLabels).not.toContain('rsolv:detected');
    expect(createdLabels).not.toContain('security');
  });
});