import { JiraAdapter } from './jira/jira-adapter';
import type { PlatformAdapter, PlatformConfig } from './types';

export class PlatformFactory {
  static create(platform: string, config: PlatformConfig): PlatformAdapter {
    switch (platform) {
      case 'jira':
        if (!config.jira) {
          throw new Error('Jira configuration is required');
        }
        return new JiraAdapter(config.jira);
      
      case 'linear':
        throw new Error('Linear integration not yet implemented');
      
      case 'gitlab':
        throw new Error('GitLab integration not yet implemented');
      
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }

  static async createAndAuthenticate(platform: string, config: PlatformConfig): Promise<PlatformAdapter> {
    const adapter = this.create(platform, config);
    await adapter.authenticate();
    return adapter;
  }
}