export type AgentName = 'TriageAgent' | 'PatchAgent' | 'VerifierAgent' | 'PRAgent';

export type RemediationStatus = 
  | 'IDLE' 
  | 'TRIAGING' 
  | 'PATCHING' 
  | 'VERIFYING' 
  | 'RETRY_NEEDED' 
  | 'VERIFIED' 
  | 'PR_READY' 
  | 'FAILED';

export interface Finding {
  id: string;
  scanner: string;
  type: 'SAST' | 'SCA' | 'SECRET' | 'IAC';
  ruleId: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string[];
  cvss: number;
  epssProbability?: number;
  blastRadiusTier?: 'LOW' | 'MEDIUM' | 'HIGH';
  filePath: string;
  startLine: number;
  endLine: number;
  vulnerableCode: string;
  astContext?: string;
  packageInfo?: {
    name: string;
    installedVersion: string;
    fixedVersion: string;
  };
}

export interface AgentLog {
  id: string;
  timestamp: string;
  agent: AgentName;
  message: string;
  type: 'info' | 'success' | 'warning' | 'error';
  details?: string;
}

export interface VerificationResult {
  passed: boolean;
  functionalTestsPassed: boolean;
  securityTestsPassed: boolean;
  syntaxValid: boolean;
  testOutput: string;
  securityOutput: string;
  durationSeconds: number;
}

export interface RemediationResult {
  finding: Finding;
  status: RemediationStatus;
  patchDiff?: string;
  patchExplanation?: string;
  retryCount: number;
  maxRetries: number;
  verification?: VerificationResult;
  prBranch?: string;
  prTitle?: string;
  prBody?: string;
  commitSha?: string;
  logs: AgentLog[];
}
