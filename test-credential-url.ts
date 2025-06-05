import { RSOLVCredentialManager } from './src/credentials/manager.js';

const manager = new RSOLVCredentialManager();
console.log('Default URL:', (manager as any).rsolvApiUrl);
console.log('Env var:', process.env.RSOLV_API_URL);
