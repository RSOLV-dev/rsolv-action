Analyze this security vulnerability:

ISSUE: Login endpoint vulnerable to timing attack
DESCRIPTION: The /api/auth/login endpoint in src/auth/login.js doesn't implement constant-time comparison for passwords, making it vulnerable to timing attacks.

An attacker could potentially determine valid passwords by measuring response times.

The password comparison on line 15 uses regular string comparison which returns early on first mismatch.

Please provide:
1. A description of the vulnerability
2. The specific file and line that needs to be fixed  
3. The exact code change needed
4. An explanation of why this fix prevents timing attacks

Please be specific about the file path and code changes.