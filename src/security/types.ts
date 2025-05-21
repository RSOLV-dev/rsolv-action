export enum VulnerabilityType {
  SQL_INJECTION = 'sql_injection',
  XSS = 'xss',
  BROKEN_AUTHENTICATION = 'broken_authentication',
  SENSITIVE_DATA_EXPOSURE = 'sensitive_data_exposure',
  XML_EXTERNAL_ENTITIES = 'xml_external_entities',
  BROKEN_ACCESS_CONTROL = 'broken_access_control',
  SECURITY_MISCONFIGURATION = 'security_misconfiguration',
  INSECURE_DESERIALIZATION = 'insecure_deserialization',
  VULNERABLE_COMPONENTS = 'vulnerable_components',
  INSUFFICIENT_LOGGING = 'insufficient_logging'
}

export interface Vulnerability {
  type: VulnerabilityType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  line: number;
  column?: number;
  message: string;
  description: string;
  cweId?: string;
  owaspCategory?: string;
  remediation?: string;
  confidence: number; // 0-100
}

export interface SecurityScanResult {
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    byType: Record<VulnerabilityType, number>;
    bySeverity: Record<string, number>;
  };
  metadata: {
    language: string;
    linesScanned: number;
    scanDuration: number;
    timestamp: string;
  };
}

export interface SecurityPattern {
  id: string;
  type: VulnerabilityType;
  name: string;
  description: string;
  patterns: {
    regex?: RegExp[];
    ast?: string[]; // AST node types to match
  };
  severity: 'low' | 'medium' | 'high' | 'critical';
  cweId: string;
  owaspCategory: string;
  languages: string[];
  remediation: string;
  examples: {
    vulnerable: string;
    secure: string;
  };
}