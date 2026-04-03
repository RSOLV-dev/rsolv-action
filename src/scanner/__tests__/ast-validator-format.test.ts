import { ASTValidator } from '../ast-validator.js';
import { Vulnerability } from '../../security/types.js';

describe('ASTValidator API Format', () => {
  it('should format files with content wrapper object', () => {
    const validator = new ASTValidator('test-key');

    // Access private method for testing
    const prepareRequest = (validator as any).prepareValidationRequest.bind(validator);

    const vulnerabilities: Vulnerability[] = [
      {
        type: 'sql_injection',
        severity: 'high',
        line: 10,
        column: 5,
        filePath: 'app.js',
        snippet: 'db.query(userInput)',
        pattern: 'sql_injection',
        confidence: 0.9
      }
    ];

    const fileContents = new Map([
      ['app.js', 'const code = "test";']
    ]);

    const request = prepareRequest(vulnerabilities, fileContents);

    // Check that files are formatted with content wrapper
    expect(request.files).toBeDefined();
    expect(request.files['app.js']).toBeDefined();
    expect(request.files['app.js'].content).toBe('const code = "test";');

    // Check that vulnerabilities include required fields
    expect(request.vulnerabilities[0].type).toBe('sql_injection');
    expect(request.vulnerabilities[0].patternId).toBe('sql_injection');

    // CRITICAL: API expects 'file' field, not 'filePath' (see platform schema at lib/rsolv_web/schemas/vulnerability.ex:322)
    expect(request.vulnerabilities[0].file).toBe('app.js');
    expect(request.vulnerabilities[0].filePath).toBeUndefined();
  });
});