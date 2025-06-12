export interface ClaudeCodeContext {
  attemptedApproaches: string[];
  partialFindings: Finding[];
  stuckPoints: string[];
  focusArea: CodeScope;
  analysisBudgetRemaining: number;
}

export interface AnalysisEscalation {
  trigger: 'context_limit' | 'complexity_threshold' | 'ambiguous_findings';
  claudeCodeContext: ClaudeCodeContext;
  escalationRequest: {
    focusArea: CodeScope;
    reasoningDepth: number;
    timeBudget: number;
  };
}

export interface CodeScope {
  files: string[];
  entryPoints: CodeLocation[];
  serviceNames?: string[];
  searchPatterns?: string[];
}

export interface CodeLocation {
  file: string;
  line: number;
  column?: number;
  functionName?: string;
}

export interface Finding {
  type: 'bug' | 'performance' | 'architecture' | 'security';
  severity: 'low' | 'medium' | 'high' | 'critical';
  location: CodeLocation;
  description: string;
  evidence: string[];
}

export interface ExecutionStep {
  location: CodeLocation;
  operation: string;
  inputs: unknown[];
  outputs: unknown[];
  stateChanges: StateChange[];
  duration?: number;
}

export interface StateChange {
  variable: string;
  oldValue: unknown;
  newValue: unknown;
  scope: 'local' | 'global' | 'instance';
}

export interface ExecutionPath {
  id: string;
  steps: ExecutionStep[];
  totalDuration?: number;
  complexity: ComplexityMetrics;
}

export interface ComplexityMetrics {
  cyclomaticComplexity: number;
  cognitiveComplexity: number;
  bigOTime: string;
  bigOSpace: string;
}

export interface PerformanceIssue {
  type: 'n_plus_one' | 'inefficient_algorithm' | 'excessive_io' | 'memory_leak';
  location: CodeLocation;
  impact: {
    estimatedLatency: number;
    affectedOperations: string[];
    frequency: number;
  };
  suggestion: string;
}

export interface SystemImpact {
  service: string;
  impactType: 'breaking' | 'performance' | 'behavioral';
  affectedEndpoints: string[];
  downstreamEffects: SystemImpact[];
}

export interface RootCause {
  type: string;
  description: string;
  evidence: CodeLocation[];
  confidence: number;
  fixStrategy: string;
}

export interface Hypothesis {
  id: string;
  description: string;
  testApproach: string;
  validated: boolean;
  evidence: string[];
}

export interface DeepAnalysisResult {
  status: 'success' | 'partial' | 'need_more_context';
  findings: {
    rootCauses: RootCause[];
    executionPaths: ExecutionPath[];
    performanceBottlenecks: PerformanceIssue[];
    crossSystemImpacts: SystemImpact[];
  };
  recommendations: {
    immediateActions: Action[];
    investigationNextSteps: string[];
    codeChangesNeeded: CodeChange[];
  };
  enrichedContext: {
    newInsights: Insight[];
    validatedHypotheses: Hypothesis[];
    ruledOutApproaches: string[];
  };
  metadata?: {
    sessionId?: string;
    totalTurns?: number;
    duration?: number;
    completedSteps?: string[];
    [key: string]: string | number | string[] | undefined;
  };
}

export interface Action {
  type: 'fix' | 'investigate' | 'refactor' | 'monitor';
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  estimatedEffort: string;
}

export interface CodeChange {
  file: string;
  changeType: 'add' | 'modify' | 'delete';
  description: string;
  suggestedCode?: string;
}

export interface Insight {
  type: string;
  description: string;
  supporting_evidence: string[];
}

// What-If Scenario Simulator types
export interface ProposedChange {
  description: string;
  diff: string;
  affectedFiles: string[];
}

export interface SimulationParameters {
  stressConditions?: Array<'high_concurrency' | 'network_latency' | 'high_error_rate'>;
  targetEntryPoint?: string;
}

export interface SimulationFinding {
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  findingType: 'performance_degradation' | 'new_bug' | 'breaking_change' | 'emergent_instability';
  description: string;
  evidence: {
    before: string;
    after: string;
  };
  location: CodeLocation;
}

export interface SimulationResult {
  summary: {
    recommendation: 'safe_to_implement' | 'proceed_with_caution' | 'high_risk_do_not_implement';
    justification: string;
  };
  findings: SimulationFinding[];
  impactComparison?: {
    before: {
      executionPath?: ExecutionPath;
      performance?: PerformanceIssue[];
    };
    after: {
      executionPath?: ExecutionPath;
      performance?: PerformanceIssue[];
    };
  };
  systemImpact?: SystemImpact;
}