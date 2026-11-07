export type AgentName = 
  | 'TriageAgent' 
  | 'PatchAgent' 
  | 'VerifierAgent' 
  | 'PRAgent' 
  | 'DASTSanitizerAgent' 
  | 'DockerfileAgent' 
  | 'ComplianceAgent'
  | 'KubernetesHardeningAgent'
  | 'TerraformRemediationAgent'
  | 'GraphQLSanitizerAgent'
  | 'SSRFRemediationAgent'
  | 'RegexDosRemediationAgent'
  | 'CORSHardeningAgent'
  | 'SSTIRemediationAgent'
  | 'OpenRedirectAgent'
  | 'MassAssignmentAgent'
  | 'RateLimitingAgent'
  | 'SessionHardeningAgent'
  | 'ContentSecurityPolicyAgent'
  | 'SQLAlchemySanitizerAgent'
  | 'XPathSanitizerAgent'
  | 'YamlDeserializationAgent'
  | 'TempFileHardeningAgent'
  | 'MissingAuthorizationAgent'
  | 'TimingAttackRemediationAgent'
  | 'ZipSlipRemediationAgent'
  | 'RandomnessHardeningAgent'
  | 'LdapSanitizerAgent'
  | 'LogInjectionSanitizerAgent'
  | 'PrototypePollutionRemediationAgent'
  | 'KeyDerivationHardeningAgent'
  | 'MakoSandboxAgent'
  | 'SymlinkTraversalAgent'
  | 'HppRemediationAgent'
  | 'SvgXxeSanitizerAgent'
  | 'IdorRemediationAgent'
  | 'PdfSsrfSanitizerAgent'
  | 'RegexTimeoutAgent'
  | 'GraphqlIntrospectionAgent'
  | 'CachePoisoningAgent'
  | 'PickleDeserializationAgent'
  | 'SstiSandboxAgent'
  | 'XpathParameterizationAgent'
  | 'MassAssignmentGuardAgent'
  | 'OpenRedirectGuardAgent';

export type ScannerType =
  | 'semgrep'
  | 'codeql'
  | 'bandit'
  | 'trivy'
  | 'snyk'
  | 'sonarqube'
  | 'kics'
  | 'horusec'
  | 'zap'
  | 'nuclei'
  | 'hadolint'
  | 'pip-audit'
  | 'npm-audit'
  | 'flawfinder'
  | 'safety'
  | 'checkov'
  | 'kubescape'
  | 'syft'
  | 'clang-tidy'
  | 'gosec'
  | 'spotbugs'
  | 'checkmarx'
  | 'semgrep-secrets'
  | 'semgrep-supply-chain'
  | 'cyclonedx'
  | 'terrascan'
  | 'fortify'
  | 'veracode'
  | 'mend'
  | 'trivy-operator'
  | 'pylint-security'
  | 'sonarqube-hotspots'
  | 'defender-devops'
  | 'contrast'
  | 'gitlab-dependency'
  | 'github-secret'
  | 'blackduck'
  | 'neuvector'
  | 'prisma-cloud'
  | 'snyk-container'
  | 'aqua'
  | 'spectral'
  | 'anchore'
  | 'appcheck'
  | 'bearer'
  | 'invicti'
  | 'insightappsec'
  | 'qualys-was'
  | 'stackhawk'
  | 'jfrog-xray'
  | 'acunetix'
  | 'sonarcloud'
  | 'lacework'
  | 'bridgecrew'
  | 'prisma-compute'
  | 'deepsource'
  | 'wiz'
  | 'mend-bolt'
  | 'orca'
  | 'prowler';

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
  type: 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'DAST' | 'CONTAINER';
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

export interface ComplianceAuditSummary {
  standard: string;
  scorePercent: number;
  passedCount: number;
  totalCount: number;
  findings: Array<{
    controlId: string;
    description: string;
    passed: boolean;
  }>;
}

export interface LicenseAuditResult {
  package: string;
  version: string;
  license: string;
  tier: 'PERMISSIVE' | 'WEAK_COPYLEFT' | 'STRONG_COPYLEFT' | 'NETWORK_COPYLEFT' | 'UNKNOWN';
  compliant: boolean;
  reason?: string;
}

