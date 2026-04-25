import type { Finding } from "../../core/types.js";

interface AuditPattern {
  id: string;
  title: string;
  severity: Finding["severity"];
  description: string;
  remediation: string;
  pattern: RegExp;
}

export const AUDIT_PATTERNS: AuditPattern[] = [
  // Secrets in code
  {
    id: "hardcoded-secret",
    title: "Hardcoded secret or API key",
    severity: "critical",
    pattern: /(api[_-]?key|secret|password|token|credential)\s*=\s*["'][A-Za-z0-9+/=_\-]{16,}["']/i,
    description: "A secret value appears to be hardcoded in source code.",
    remediation: "Move secrets to environment variables and add the file to .gitignore.",
  },
  {
    id: "aws-key",
    title: "AWS access key hardcoded",
    severity: "critical",
    pattern: /AKIA[0-9A-Z]{16}/,
    description: "An AWS access key ID is hardcoded in source code.",
    remediation: "Revoke the key immediately, rotate it, and use IAM roles or environment variables.",
  },
  {
    id: "private-key-pem",
    title: "Private key material in source",
    severity: "critical",
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    description: "A PEM-encoded private key is embedded in source code.",
    remediation: "Remove the key, rotate all associated certificates, and use a secrets manager.",
  },

  // Dangerous functions
  {
    id: "eval-usage",
    title: "Use of eval()",
    severity: "high",
    pattern: /\beval\s*\(/,
    description: "eval() executes arbitrary code, enabling remote code execution if user input reaches it.",
    remediation: "Replace eval() with safe alternatives. If dynamic code is required, use a sandbox.",
  },
  {
    id: "exec-shell",
    title: "Shell command execution with variable input",
    severity: "high",
    pattern: /\b(exec|execSync|spawn|spawnSync|system|popen|subprocess\.call)\s*\([^)]*\$/,
    description: "Shell commands are being constructed with variable input, risking command injection.",
    remediation: "Use parameterized command execution (exec with args array). Never concatenate user input into shell strings.",
  },

  // SQL injection signals
  {
    id: "sql-concat",
    title: "SQL query string concatenation",
    severity: "high",
    pattern: /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\+.*(?:req\.|params\.|query\.|body\.)/i,
    description: "SQL query appears to be built by string concatenation with request data, enabling SQL injection.",
    remediation: "Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
  },

  // Insecure crypto
  {
    id: "md5-usage",
    title: "MD5 used for security purpose",
    severity: "medium",
    pattern: /createHash\(['"]md5['"]\)/,
    description: "MD5 is cryptographically broken and unsuitable for passwords, signatures, or integrity checks.",
    remediation: "Use SHA-256 or better for integrity checks. Use bcrypt/argon2 for passwords.",
  },
  {
    id: "weak-random",
    title: "Math.random() used for security-sensitive value",
    severity: "medium",
    pattern: /Math\.random\(\).*(token|secret|key|id|nonce|salt|session)/i,
    description: "Math.random() is not cryptographically secure and must not be used for tokens or secrets.",
    remediation: "Use crypto.getRandomValues() or crypto.randomBytes().",
  },

  // Overly permissive CORS
  {
    id: "cors-wildcard",
    title: "CORS wildcard with credentials",
    severity: "high",
    pattern: /Access-Control-Allow-Origin['":\s]+\*/,
    description: "Wildcard CORS allows any origin to make requests. Combined with credentials, this enables CSRF.",
    remediation: "Restrict Access-Control-Allow-Origin to trusted origins. Never use * with credentials: true.",
  },

  // Prototype pollution
  {
    id: "prototype-pollution",
    title: "Potential prototype pollution",
    severity: "high",
    pattern: /\[['"]__proto__['"]\]|\.__proto__\s*=|Object\.prototype\[/,
    description: "Direct writes to __proto__ or Object.prototype can enable prototype pollution attacks.",
    remediation: "Use Object.create(null) for accumulator objects. Validate keys before setting.",
  },

  // Path traversal
  {
    id: "path-traversal",
    title: "Potential path traversal",
    severity: "high",
    pattern: /(readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|params\.|query\.|body\.)/,
    description: "File system operations may use unvalidated user-supplied paths, enabling path traversal.",
    remediation: "Resolve and normalize paths, then assert they reside within an allowed base directory.",
  },

  // Verbose error exposure
  {
    id: "error-stack-exposed",
    title: "Error stack trace sent to client",
    severity: "medium",
    pattern: /res\.(send|json)\s*\([^)]*\.stack/,
    description: "Stack traces sent to HTTP clients expose internal file paths and framework versions.",
    remediation: "Log stack traces server-side only. Return generic error messages to clients.",
  },

  // Disabled security checks
  {
    id: "ssl-verify-disabled",
    title: "SSL certificate verification disabled",
    severity: "high",
    pattern: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER.*false/i,
    description: "Disabling SSL certificate verification exposes the application to MITM attacks.",
    remediation: "Never disable SSL verification in production. Fix the certificate chain instead.",
  },
];
