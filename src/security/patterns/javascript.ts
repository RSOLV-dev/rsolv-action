import { SecurityPattern, VulnerabilityType } from '../types.js';

export const javascriptSecurityPatterns: SecurityPattern[] = [
  // Basic JavaScript/TypeScript Patterns (for backward compatibility)
  {
    id: 'sql-injection-concat',
    type: VulnerabilityType.SQL_INJECTION,
    name: 'SQL Injection via String Concatenation',
    description: 'Detects SQL injection vulnerabilities from string concatenation',
    patterns: {
      regex: [
        /["'`].*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?["'`]\s*\+\s*\w+/gi,
        /query.*?=.*?["'`].*?(WHERE|SET|VALUES).*?["'`]\s*\+/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Use parameterized queries or prepared statements',
    examples: {
      vulnerable: 'const query = "SELECT * FROM users WHERE id = " + userId;',
      secure: 'const query = "SELECT * FROM users WHERE id = ?"; db.query(query, [userId]);'
    }
  },
  {
    id: 'sql-injection-template',
    type: VulnerabilityType.SQL_INJECTION,
    name: 'SQL Injection via Template Literals',
    description: 'Detects SQL injection vulnerabilities from template literal interpolation',
    patterns: {
      regex: [
        /`.*?(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?\$\{[^}]+\}.*?`/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-89',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Use parameterized queries instead of template literals for SQL',
    examples: {
      vulnerable: 'const query = `SELECT * FROM users WHERE name = \'${userName}\'`;',
      secure: 'const query = "SELECT * FROM users WHERE name = ?"; db.query(query, [userName]);'
    }
  },
  {
    id: 'xss-inner-html',
    type: VulnerabilityType.XSS,
    name: 'XSS via innerHTML Assignment',
    description: 'Detects XSS vulnerabilities from innerHTML assignments',
    patterns: {
      regex: [
        /\.innerHTML\s*=\s*[^;]+(?!\.replace|\.escape|\.sanitize)/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Use textContent or sanitize input before setting innerHTML',
    examples: {
      vulnerable: 'element.innerHTML = userInput;',
      secure: 'element.textContent = userInput; // or use DOMPurify.sanitize(userInput)'
    }
  },
  {
    id: 'xss-document-write',
    type: VulnerabilityType.XSS,
    name: 'XSS via document.write',
    description: 'Detects XSS vulnerabilities from document.write calls',
    patterns: {
      regex: [
        /document\.write\s*\([^)]*\w+[^)]*\)/gi,
        /\$\([^)]+\)\.html\s*\([^)]*\w+[^)]*\)/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Avoid document.write and use safe DOM manipulation methods',
    examples: {
      vulnerable: 'document.write(userContent);',
      secure: 'const div = document.createElement("div"); div.textContent = userContent;'
    }
  },
  {
    id: 'broken-access-control-no-auth',
    type: VulnerabilityType.BROKEN_ACCESS_CONTROL,
    name: 'Missing Authentication Check',
    description: 'Detects endpoints without proper authentication checks',
    patterns: {
      regex: [
        /app\.(get|post|put|delete|patch)\s*\([^,]+,\s*(?!.*auth|.*login|.*verify|.*token)[^)]*\)/gi,
        /router\.(get|post|put|delete|patch)\s*\([^,]+,\s*(?!.*auth|.*login|.*verify|.*token)[^)]*\)/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-862',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript'],
    remediation: 'Add proper authentication middleware to protect endpoints',
    examples: {
      vulnerable: 'app.get("/admin/users", (req, res) => { /* handler */ });',
      secure: 'app.get("/admin/users", authenticateUser, (req, res) => { /* handler */ });'
    }
  },

  // React-Specific Patterns
  {
    id: 'react-dangerously-set-html',
    type: VulnerabilityType.XSS,
    name: 'React dangerouslySetInnerHTML XSS',
    description: 'Detects XSS vulnerabilities in React dangerouslySetInnerHTML',
    patterns: {
      regex: [
        /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*[^}]*(?!sanitize|DOMPurify)[^}]*\}\s*\}/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Sanitize HTML content before using dangerouslySetInnerHTML or use safe alternatives',
    examples: {
      vulnerable: '<div dangerouslySetInnerHTML={{ __html: userContent }} />',
      secure: '<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />'
    }
  },
  {
    id: 'react-eval-href',
    type: VulnerabilityType.XSS,
    name: 'React javascript: protocol in href',
    description: 'Detects potential XSS through javascript: protocol in React href',
    patterns: {
      regex: [
        /href\s*=\s*\{[^}]*(?!sanitize|validate)[^}]*\}/gi,
        /<a[^>]*href\s*=\s*["']javascript:/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-79',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Validate and sanitize URLs before using in href attributes',
    examples: {
      vulnerable: '<a href={userProvidedUrl}>Link</a>',
      secure: '<a href={sanitizeUrl(userProvidedUrl)}>Link</a>'
    }
  },
  {
    id: 'react-unvalidated-redirect',
    type: VulnerabilityType.UNVALIDATED_REDIRECT,
    name: 'React Router Unvalidated Redirect',
    description: 'Detects unvalidated redirects in React Router',
    patterns: {
      regex: [
        /navigate\s*\(\s*(?!.*validate|.*whitelist)[^)]*req\.|navigate\s*\(\s*(?!.*validate|.*whitelist)[^)]*params\./gi,
        /window\.location\.href\s*=\s*(?!.*validate|.*whitelist)[^;]*req\./gi
      ]
    },
    severity: 'medium',
    cweId: 'CWE-601',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript'],
    remediation: 'Validate redirect URLs against a whitelist before navigation',
    examples: {
      vulnerable: 'navigate(req.query.redirect);',
      secure: 'if (isValidRedirect(req.query.redirect)) navigate(req.query.redirect);'
    }
  },

  // Node.js-Specific Patterns
  {
    id: 'nodejs-command-injection',
    type: VulnerabilityType.COMMAND_INJECTION,
    name: 'Node.js Command Injection',
    description: 'Detects command injection vulnerabilities in Node.js child_process',
    patterns: {
      regex: [
        /child_process\.(exec|spawn|execFile)\s*\([^)]*(?!.*sanitize|.*validate)[^)]*\+[^)]*\)/gi,
        /require\(['"]child_process['"]\)\.(exec|spawn)\s*\([^)]*\$\{/gi
      ]
    },
    severity: 'critical',
    cweId: 'CWE-78',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Use execFile with explicit arguments array instead of exec, validate input',
    examples: {
      vulnerable: 'exec(`ls ${userInput}`);',
      secure: 'execFile("ls", [sanitizedInput]);'
    }
  },
  {
    id: 'nodejs-path-traversal',
    type: VulnerabilityType.PATH_TRAVERSAL,
    name: 'Node.js Path Traversal',
    description: 'Detects path traversal vulnerabilities in file operations',
    patterns: {
      regex: [
        /fs\.(readFile|writeFile|readdir|unlink|mkdir|rmdir)\s*\([^)]*(?!.*path\.join|.*resolve)[^)]*req\./gi,
        /require\(['"]fs['"]\)\.\w+\s*\([^)]*\.\.\//gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-22',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript'],
    remediation: 'Use path.join() and validate paths to prevent directory traversal',
    examples: {
      vulnerable: 'fs.readFile(req.params.filename);',
      secure: 'fs.readFile(path.join(SAFE_DIR, path.basename(req.params.filename)));'
    }
  },
  {
    id: 'nodejs-prototype-pollution',
    type: VulnerabilityType.PROTOTYPE_POLLUTION,
    name: 'Node.js Prototype Pollution',
    description: 'Detects potential prototype pollution vulnerabilities',
    patterns: {
      regex: [
        /Object\.assign\s*\(\s*(?!.*{}\s*,)[^,)]+,\s*req\./gi,
        /\[['"]__proto__['"]\]/gi,
        /\[['"]constructor['"]\]\[['"]prototype['"]\]/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-1321',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Validate object keys and use Object.create(null) for safe objects',
    examples: {
      vulnerable: 'Object.assign(config, req.body);',
      secure: 'Object.assign(config, sanitizeObject(req.body));'
    }
  },
  {
    id: 'nodejs-ssrf',
    type: VulnerabilityType.SSRF,
    name: 'Node.js Server-Side Request Forgery',
    description: 'Detects SSRF vulnerabilities in HTTP requests',
    patterns: {
      regex: [
        /axios\.(get|post|put|delete)\s*\([^)]*(?!.*validate|.*whitelist)[^)]*req\./gi,
        /fetch\s*\([^)]*(?!.*validate|.*whitelist)[^)]*req\./gi,
        /request\s*\([^)]*url:\s*[^}]*req\./gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - Server-Side Request Forgery',
    languages: ['javascript', 'typescript'],
    remediation: 'Validate and whitelist URLs before making HTTP requests',
    examples: {
      vulnerable: 'axios.get(req.body.url);',
      secure: 'if (isWhitelistedUrl(req.body.url)) axios.get(req.body.url);'
    }
  },

  // TypeScript-Specific Patterns
  {
    id: 'typescript-any-type',
    type: VulnerabilityType.TYPE_CONFUSION,
    name: 'TypeScript Unsafe Any Type',
    description: 'Detects use of any type that may lead to security issues',
    patterns: {
      regex: [
        /:\s*any\s*[;,\s)]/gi,
        /<any>/gi,
        /as\s+any\s*[;,\s)]/gi
      ]
    },
    severity: 'low',
    cweId: 'CWE-843',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['typescript'],
    remediation: 'Use specific types instead of any to maintain type safety',
    examples: {
      vulnerable: 'function processUser(data: any) { }',
      secure: 'function processUser(data: User) { }'
    }
  },
  {
    id: 'typescript-non-null-assertion',
    type: VulnerabilityType.NULL_POINTER_DEREFERENCE,
    name: 'TypeScript Non-Null Assertion',
    description: 'Detects unsafe non-null assertions that may cause runtime errors',
    patterns: {
      regex: [
        /\w+!\.(?!length|toString|valueOf)/gi
      ]
    },
    severity: 'medium',
    cweId: 'CWE-476',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['typescript'],
    remediation: 'Use proper null checks instead of non-null assertions',
    examples: {
      vulnerable: 'const name = user!.name;',
      secure: 'const name = user?.name || "default";'
    }
  },

  // Express.js Specific Patterns
  {
    id: 'express-csrf-missing',
    type: VulnerabilityType.CSRF,
    name: 'Express Missing CSRF Protection',
    description: 'Detects missing CSRF protection in Express applications',
    patterns: {
      regex: [
        /app\.(post|put|delete|patch)\s*\([^)]*(?!.*csrf|.*csurf)[^)]*\)/gi
      ]
    },
    severity: 'medium',
    cweId: 'CWE-352',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript'],
    remediation: 'Implement CSRF protection using csurf or similar middleware',
    examples: {
      vulnerable: 'app.post("/api/transfer", handleTransfer);',
      secure: 'app.post("/api/transfer", csrfProtection, handleTransfer);'
    }
  },
  {
    id: 'express-rate-limit-missing',
    type: VulnerabilityType.DENIAL_OF_SERVICE,
    name: 'Express Missing Rate Limiting',
    description: 'Detects missing rate limiting on sensitive endpoints',
    patterns: {
      regex: [
        /app\.(post|put)\s*\(['"]\/(login|auth|api\/auth|password)[^)]*(?!.*limit|.*rate)[^)]*\)/gi
      ]
    },
    severity: 'medium',
    cweId: 'CWE-770',
    owaspCategory: 'A04:2021 - Insecure Design',
    languages: ['javascript', 'typescript'],
    remediation: 'Implement rate limiting on authentication endpoints',
    examples: {
      vulnerable: 'app.post("/login", handleLogin);',
      secure: 'app.post("/login", rateLimiter, handleLogin);'
    }
  },

  // JWT Specific Patterns
  {
    id: 'jwt-weak-secret',
    type: VulnerabilityType.WEAK_CRYPTO,
    name: 'JWT Weak Secret',
    description: 'Detects weak or hardcoded JWT secrets',
    patterns: {
      regex: [
        /jwt\.sign\s*\([^,]+,\s*["'][^"']{1,10}["']/gi,
        /secret:\s*["'](?:secret|password|123456|admin)["']/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-798',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript'],
    remediation: 'Use strong, randomly generated secrets from environment variables',
    examples: {
      vulnerable: 'jwt.sign(payload, "secret");',
      secure: 'jwt.sign(payload, process.env.JWT_SECRET);'
    }
  },
  {
    id: 'jwt-none-algorithm',
    type: VulnerabilityType.BROKEN_AUTHENTICATION,
    name: 'JWT None Algorithm',
    description: 'Detects JWT verification allowing none algorithm',
    patterns: {
      regex: [
        /algorithms:\s*\[[^\]]*['"]none['"]/gi,
        /jwt\.verify\s*\([^)]+\{\s*algorithms:\s*\[[^\]]*['"]none['"]/gi
      ]
    },
    severity: 'critical',
    cweId: 'CWE-347',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript'],
    remediation: 'Never allow "none" algorithm in JWT verification',
    examples: {
      vulnerable: 'jwt.verify(token, secret, { algorithms: ["HS256", "none"] });',
      secure: 'jwt.verify(token, secret, { algorithms: ["HS256"] });'
    }
  },

  // MongoDB Specific Patterns
  {
    id: 'mongodb-injection',
    type: VulnerabilityType.NOSQL_INJECTION,
    name: 'MongoDB NoSQL Injection',
    description: 'Detects NoSQL injection vulnerabilities in MongoDB queries',
    patterns: {
      regex: [
        /\$where.*req\.|find\s*\(\s*\{[^}]*\$where/gi,
        /collection\.\w+\s*\(\s*\{[^}]*:\s*req\./gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-943',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Validate and sanitize input before using in MongoDB queries',
    examples: {
      vulnerable: 'db.users.find({ username: req.body.username });',
      secure: 'db.users.find({ username: validator.escape(req.body.username) });'
    }
  },

  // GraphQL Specific Patterns
  {
    id: 'graphql-introspection',
    type: VulnerabilityType.INFORMATION_DISCLOSURE,
    name: 'GraphQL Introspection Enabled',
    description: 'Detects GraphQL introspection enabled in production',
    patterns: {
      regex: [
        /introspection:\s*true/gi,
        /GraphQLSchema.*introspection:\s*true/gi
      ]
    },
    severity: 'medium',
    cweId: 'CWE-200',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript'],
    remediation: 'Disable GraphQL introspection in production environments',
    examples: {
      vulnerable: 'new GraphQLServer({ schema, introspection: true });',
      secure: 'new GraphQLServer({ schema, introspection: process.env.NODE_ENV === "development" });'
    }
  },

  // WebSocket Specific Patterns
  {
    id: 'websocket-origin-validation',
    type: VulnerabilityType.IMPROPER_INPUT_VALIDATION,
    name: 'WebSocket Missing Origin Validation',
    description: 'Detects missing origin validation in WebSocket connections',
    patterns: {
      regex: [
        /ws\.on\s*\(\s*['"]connection['"]\s*,\s*(?!.*origin|.*validate)[^}]*\}/gi,
        /io\.on\s*\(\s*['"]connection['"]\s*,\s*(?!.*origin|.*auth)[^}]*\}/gi
      ]
    },
    severity: 'medium',
    cweId: 'CWE-346',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    languages: ['javascript', 'typescript'],
    remediation: 'Validate WebSocket connection origins',
    examples: {
      vulnerable: 'ws.on("connection", (socket) => { /* handler */ });',
      secure: 'ws.on("connection", (socket, req) => { if (validateOrigin(req)) { /* handler */ } });'
    }
  },

  // Electron Specific Patterns
  {
    id: 'electron-node-integration',
    type: VulnerabilityType.SECURITY_MISCONFIGURATION,
    name: 'Electron Node Integration Enabled',
    description: 'Detects unsafe Electron configurations with Node integration',
    patterns: {
      regex: [
        /nodeIntegration:\s*true/gi,
        /contextIsolation:\s*false/gi,
        /webSecurity:\s*false/gi
      ]
    },
    severity: 'critical',
    cweId: 'CWE-829',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    languages: ['javascript', 'typescript'],
    remediation: 'Disable Node integration and enable context isolation',
    examples: {
      vulnerable: 'new BrowserWindow({ webPreferences: { nodeIntegration: true } });',
      secure: 'new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });'
    }
  },

  // React Native Specific Patterns
  {
    id: 'react-native-storage',
    type: VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
    name: 'React Native Insecure Storage',
    description: 'Detects sensitive data stored insecurely in React Native',
    patterns: {
      regex: [
        /AsyncStorage\.setItem\s*\([^,]+(?:password|token|secret|key)/gi,
        /SecureStore\.setItemAsync.*encrypt:\s*false/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-922',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    languages: ['javascript', 'typescript'],
    remediation: 'Use secure storage solutions for sensitive data',
    examples: {
      vulnerable: 'AsyncStorage.setItem("userToken", token);',
      secure: 'SecureStore.setItemAsync("userToken", token, { keychainAccessible: SecureStore.WHEN_UNLOCKED });'
    }
  },

  // Next.js Specific Patterns
  {
    id: 'nextjs-api-auth',
    type: VulnerabilityType.BROKEN_ACCESS_CONTROL,
    name: 'Next.js API Route Missing Authentication',
    description: 'Detects Next.js API routes without authentication',
    patterns: {
      regex: [
        /export\s+default\s+(?:async\s+)?function\s*\([^)]*\)\s*\{[^}]*(?!.*auth|.*session|.*jwt)[^}]*\}/gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-306',
    owaspCategory: 'A01:2021 - Broken Access Control',
    languages: ['javascript', 'typescript'],
    remediation: 'Add authentication checks to API routes',
    examples: {
      vulnerable: 'export default function handler(req, res) { /* unprotected */ }',
      secure: 'export default withAuth(function handler(req, res) { /* protected */ });'
    }
  }
];

// Enhanced existing patterns with more specific detections
export const enhancedJavaScriptPatterns: SecurityPattern[] = [
  // A03:2021 - Enhanced Injection Patterns
  {
    id: 'template-injection',
    type: VulnerabilityType.TEMPLATE_INJECTION,
    name: 'Server-Side Template Injection',
    description: 'Detects template injection vulnerabilities',
    patterns: {
      regex: [
        /render\s*\([^,]+,\s*\{[^}]*:\s*req\./gi,
        /compile\s*\([^)]*req\./gi,
        /new\s+Function\s*\([^)]*req\./gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-94',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Sanitize user input before using in templates',
    examples: {
      vulnerable: 'res.render("template", { data: req.body.input });',
      secure: 'res.render("template", { data: sanitize(req.body.input) });'
    }
  },
  {
    id: 'ldap-injection',
    type: VulnerabilityType.LDAP_INJECTION,
    name: 'LDAP Injection',
    description: 'Detects LDAP injection vulnerabilities',
    patterns: {
      regex: [
        /ldap.*search.*filter.*\+.*req\./gi,
        /\(\w+=[^)]*\+[^)]*req\./gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-90',
    owaspCategory: 'A03:2021 - Injection',
    languages: ['javascript', 'typescript'],
    remediation: 'Use parameterized LDAP queries and escape special characters',
    examples: {
      vulnerable: 'ldap.search(`(uid=${req.body.username})`);',
      secure: 'ldap.search(`(uid=${ldap.escape(req.body.username)})`);'
    }
  },

  // A10:2021 - Server-Side Request Forgery
  {
    id: 'ssrf-dns-rebinding',
    type: VulnerabilityType.SSRF,
    name: 'SSRF with DNS Rebinding',
    description: 'Detects SSRF vulnerabilities susceptible to DNS rebinding',
    patterns: {
      regex: [
        /request\s*\.\w+\s*\([^)]*hostname:[^}]*req\./gi,
        /http\.\w+\s*\([^)]*host:[^}]*req\./gi
      ]
    },
    severity: 'high',
    cweId: 'CWE-918',
    owaspCategory: 'A10:2021 - Server-Side Request Forgery',
    languages: ['javascript', 'typescript'],
    remediation: 'Validate hostnames and use IP allowlists',
    examples: {
      vulnerable: 'http.get({ hostname: req.body.host });',
      secure: 'if (isAllowedHost(req.body.host)) http.get({ hostname: req.body.host });'
    }
  }
];

// Combine all patterns
export const allJavaScriptPatterns = [
  ...javascriptSecurityPatterns,
  ...enhancedJavaScriptPatterns
];