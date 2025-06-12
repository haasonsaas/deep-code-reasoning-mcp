import type {
  ClaudeCodeContext,
  DeepAnalysisResult,
  CodeLocation,
  SimulationResult,
  ProposedChange,
  SimulationParameters,
} from '../models/types.js';
import { GeminiService } from '../services/GeminiService.js';
import { ConversationalGeminiService } from '../services/ConversationalGeminiService.js';
import { ConversationManager } from '../services/ConversationManager.js';
import { SecureCodeReader } from '../utils/SecureCodeReader.js';
import { ErrorClassifier } from '../utils/ErrorClassifier.js';
import { ConversationLockedError, SessionNotFoundError } from '../errors/index.js';

export class DeepCodeReasonerV2 {
  private geminiService: GeminiService;
  private conversationalGemini: ConversationalGeminiService;
  private conversationManager: ConversationManager;
  private codeReader: SecureCodeReader;

  constructor(geminiApiKey: string) {
    this.geminiService = new GeminiService(geminiApiKey);
    this.conversationalGemini = new ConversationalGeminiService(geminiApiKey);
    this.conversationManager = new ConversationManager();
    this.codeReader = new SecureCodeReader();
  }

  async escalateFromClaudeCode(
    context: ClaudeCodeContext,
    analysisType: string,
    depthLevel: number,
  ): Promise<DeepAnalysisResult> {
    const startTime = Date.now();
    const timeoutMs = context.analysisBudgetRemaining * 1000;

    try {
      // Read all relevant code files
      const codeFiles = await this.codeReader.readCodeFiles(context.focusArea);

      // Enrich with related files if depth > 3
      if (depthLevel > 3) {
        await this.enrichWithRelatedFiles(context, codeFiles);
      }

      // Send to Gemini for deep analysis
      const result = await this.geminiService.analyzeWithGemini(
        context,
        analysisType,
        codeFiles,
      );

      // Check timeout
      const elapsedTime = Date.now() - startTime;
      if (elapsedTime > timeoutMs) {
        result.status = 'partial';
      }

      return result;
    } catch (error) {
      console.error('Deep reasoning failed:', error);
      return this.createErrorResult(error as Error, context);
    }
  }

  private async enrichWithRelatedFiles(
    context: ClaudeCodeContext,
    codeFiles: Map<string, string>,
  ): Promise<void> {
    // Find and add related files (tests, implementations, etc.)
    for (const file of context.focusArea.files) {
      const relatedFiles = await this.codeReader.findRelatedFiles(file);

      for (const relatedFile of relatedFiles) {
        if (!codeFiles.has(relatedFile)) {
          try {
            const content = await this.codeReader.readFile(relatedFile);
            codeFiles.set(relatedFile, content);
          } catch (error) {
            // Skip files that can't be read
          }
        }
      }
    }
  }

  async traceExecutionPath(
    entryPoint: CodeLocation,
    maxDepth: number = 10,
    _includeDataFlow: boolean = true,
  ): Promise<{
    analysis: string;
    filesAnalyzed: string[];
  }> {
    // Get code context around entry point
    const _context = await this.codeReader.readCodeContext(entryPoint, 100);

    // Find related files
    const relatedFiles = await this.codeReader.findRelatedFiles(entryPoint.file);
    const codeFiles = new Map<string, string>();

    // Read entry point file
    codeFiles.set(entryPoint.file, await this.codeReader.readFile(entryPoint.file));

    // Read related files up to maxDepth
    for (let i = 0; i < Math.min(relatedFiles.length, maxDepth); i++) {
      const content = await this.codeReader.readFile(relatedFiles[i]);
      codeFiles.set(relatedFiles[i], content);
    }

    // Use Gemini to trace execution
    const analysis = await this.geminiService.performExecutionTraceAnalysis(
      codeFiles,
      entryPoint,
    );

    return {
      analysis,
      filesAnalyzed: Array.from(codeFiles.keys()),
    };
  }

  async analyzeCrossSystemImpact(
    changeScope: string[],
    impactTypes?: string[],
  ): Promise<{
    analysis: string;
    filesAnalyzed: string[];
    impactTypes: string[];
  }> {
    const codeFiles = new Map<string, string>();

    // Read all files in change scope
    for (const file of changeScope) {
      try {
        const content = await this.codeReader.readFile(file);
        codeFiles.set(file, content);

        // Also read related service files
        const relatedFiles = await this.codeReader.findRelatedFiles(file, ['Service', 'Controller', 'Client']);
        for (const related of relatedFiles) {
          const relatedContent = await this.codeReader.readFile(related);
          codeFiles.set(related, relatedContent);
        }
      } catch (error) {
        console.error(`Failed to read ${file}:`, error);
      }
    }

    // Use Gemini for cross-system analysis
    const analysis = await this.geminiService.performCrossSystemAnalysis(
      codeFiles,
      changeScope,
    );

    return {
      analysis,
      filesAnalyzed: Array.from(codeFiles.keys()),
      impactTypes: impactTypes || ['breaking', 'performance', 'behavioral'],
    };
  }

  async analyzePerformance(
    entryPoint: CodeLocation,
    profileDepth: number = 3,
    suspectedIssues?: string[],
  ): Promise<{
    analysis: string;
    filesAnalyzed: string[];
  }> {
    const codeFiles = new Map<string, string>();

    // Read entry point and related files
    codeFiles.set(entryPoint.file, await this.codeReader.readFile(entryPoint.file));

    // Find files that might affect performance
    const performancePatterns = ['Service', 'Repository', 'Query', 'Cache', 'Database'];
    const relatedFiles = await this.codeReader.findRelatedFiles(entryPoint.file, performancePatterns);

    // Read up to profileDepth related files
    for (let i = 0; i < Math.min(relatedFiles.length, profileDepth * 3); i++) {
      try {
        const content = await this.codeReader.readFile(relatedFiles[i]);
        codeFiles.set(relatedFiles[i], content);
      } catch (error) {
        // Skip unreadable files
      }
    }

    // Use Gemini for performance analysis
    const analysis = await this.geminiService.performPerformanceAnalysis(
      codeFiles,
      suspectedIssues || [],
    );

    return {
      analysis,
      filesAnalyzed: Array.from(codeFiles.keys()),
    };
  }

  async testHypothesis(
    hypothesis: string,
    codeScope: string[],
    testApproach: string,
  ): Promise<{
    hypothesis: string;
    testApproach: string;
    analysis: string;
    filesAnalyzed: string[];
  }> {
    const codeFiles = new Map<string, string>();

    // Read all files in scope
    for (const file of codeScope) {
      try {
        const content = await this.codeReader.readFile(file);
        codeFiles.set(file, content);
      } catch (error) {
        console.error(`Failed to read ${file}:`, error);
      }
    }

    // Use Gemini to test hypothesis
    const analysis = await this.geminiService.testHypothesis(
      hypothesis,
      codeFiles,
      testApproach,
    );

    return {
      hypothesis,
      testApproach,
      analysis,
      filesAnalyzed: Array.from(codeFiles.keys()),
    };
  }

  private createErrorResult(error: Error, context: ClaudeCodeContext): DeepAnalysisResult {
    // Extract structured error information
    const errorDetails = this.extractErrorDetails(error);

    return {
      status: 'partial',
      findings: {
        rootCauses: errorDetails.rootCauses,
        executionPaths: [],
        performanceBottlenecks: [],
        crossSystemImpacts: [],
      },
      recommendations: {
        immediateActions: [
          {
            type: 'investigate',
            description: errorDetails.description,
            priority: 'high',
            estimatedEffort: '1 hour',
          },
        ],
        investigationNextSteps: errorDetails.nextSteps,
        codeChangesNeeded: [],
      },
      enrichedContext: {
        newInsights: [{
          type: 'error',
          description: errorDetails.insight,
          supporting_evidence: [error.stack || error.message],
        }],
        validatedHypotheses: [],
        ruledOutApproaches: context.attemptedApproaches,
      },
      metadata: {
        errorType: error.name,
        errorCode: errorDetails.code,
        errorSource: errorDetails.source,
      },
    };
  }

  private extractErrorDetails(error: Error): {
    description: string;
    rootCauses: any[];
    nextSteps: string[];
    insight: string;
    code?: string;
    source: string;
  } {
    const classification = ErrorClassifier.classify(error);
    const nextSteps = ErrorClassifier.getNextSteps(classification);
    const message = error.message;

    // Map classification to detailed error structure
    switch (classification.category) {
      case 'api':
        return {
          description: classification.description,
          rootCauses: [{
            type: classification.code === 'RATE_LIMIT_ERROR' ? 'performance' : 'configuration',
            description: classification.code === 'RATE_LIMIT_ERROR'
              ? 'API rate limit or quota exceeded'
              : 'Gemini API authentication or configuration issue',
            location: { file: 'ConversationalGeminiService.ts', line: 0 },
            evidence: [message],
          }],
          nextSteps,
          insight: classification.code === 'RATE_LIMIT_ERROR'
            ? 'The system is making too many API requests in a short time period'
            : 'The Gemini API service is not properly configured or authenticated',
          code: classification.code,
          source: 'external_api',
        };

      case 'filesystem':
        return {
          description: classification.description,
          rootCauses: [{
            type: 'architecture',
            description: 'File access or permission issue',
            location: { file: 'CodeReader.ts', line: 0 },
            evidence: [message],
          }],
          nextSteps,
          insight: 'The code reader cannot access required files',
          code: classification.code || 'FILE_ACCESS_ERROR',
          source: 'filesystem',
        };

      case 'session':
        return {
          description: classification.description,
          rootCauses: [{
            type: 'architecture',
            description: 'Conversation session state issue',
            location: { file: 'ConversationManager.ts', line: 0 },
            evidence: [message],
          }],
          nextSteps,
          insight: 'The conversation session is in an invalid state or does not exist',
          code: classification.code || 'SESSION_ERROR',
          source: 'internal',
        };

      default:
        return {
          description: classification.description,
          rootCauses: [{
            type: 'unknown',
            description: error.name || 'Unknown error',
            location: { file: 'unknown', line: 0 },
            evidence: [message, error.stack || ''],
          }],
          nextSteps,
          insight: 'An unexpected error occurred during deep code analysis',
          code: 'UNKNOWN_ERROR',
          source: 'unknown',
        };
    }
  }

  // Conversational methods
  async startConversation(
    context: ClaudeCodeContext,
    analysisType: string,
    initialQuestion?: string,
  ): Promise<{
    sessionId: string;
    initialResponse: string;
    suggestedFollowUps: string[];
    status: 'active';
  }> {
    try {
      // Create session
      const sessionId = this.conversationManager.createSession(context);

      // Read relevant code files
      const codeFiles = await this.codeReader.readCodeFiles(context.focusArea);

      // Start Gemini conversation
      const { response, suggestedFollowUps } = await this.conversationalGemini.startConversation(
        sessionId,
        context,
        analysisType,
        codeFiles,
        initialQuestion,
      );

      // Track conversation turn
      this.conversationManager.addTurn(sessionId, 'gemini', response, {
        analysisType,
        questions: suggestedFollowUps,
      });

      return {
        sessionId,
        initialResponse: response,
        suggestedFollowUps,
        status: 'active',
      };
    } catch (error) {
      console.error('Failed to start conversation:', error);
      throw error;
    }
  }

  async continueConversation(
    sessionId: string,
    message: string,
    includeCodeSnippets?: boolean,
  ): Promise<{
    response: string;
    analysisProgress: number;
    canFinalize: boolean;
    status: string;
  }> {
    // Acquire lock before processing
    const lockAcquired = this.conversationManager.acquireLock(sessionId);
    if (!lockAcquired) {
      throw new ConversationLockedError(sessionId);
    }

    try {
      // Validate session
      const session = this.conversationManager.getSession(sessionId);
      if (!session) {
        throw new SessionNotFoundError(sessionId);
      }

      // Add Claude's message to conversation history
      this.conversationManager.addTurn(sessionId, 'claude', message);

      // Continue with Gemini
      const { response, analysisProgress, canFinalize } = await this.conversationalGemini.continueConversation(
        sessionId,
        message,
        includeCodeSnippets,
      );

      // Track Gemini's response
      this.conversationManager.addTurn(sessionId, 'gemini', response);

      // Update progress
      this.conversationManager.updateProgress(sessionId, {
        confidenceLevel: analysisProgress,
      });

      return {
        response,
        analysisProgress,
        canFinalize,
        status: session.status,
      };
    } catch (error) {
      console.error('Failed to continue conversation:', error);
      throw error;
    } finally {
      // Always release lock
      this.conversationManager.releaseLock(sessionId);
    }
  }

  async finalizeConversation(
    sessionId: string,
    summaryFormat?: 'detailed' | 'concise' | 'actionable',
  ): Promise<DeepAnalysisResult> {
    // Acquire lock before processing
    const lockAcquired = this.conversationManager.acquireLock(sessionId);
    if (!lockAcquired) {
      throw new ConversationLockedError(sessionId);
    }

    try {
      // Validate session
      const session = this.conversationManager.getSession(sessionId);
      if (!session) {
        throw new SessionNotFoundError(sessionId);
      }

      // Get final analysis from Gemini
      const result = await this.conversationalGemini.finalizeConversation(
        sessionId,
        summaryFormat || 'detailed',
      );

      // Extract additional insights from conversation manager
      const conversationResults = this.conversationManager.extractResults(sessionId);

      // Merge results
      return {
        ...result,
        metadata: {
          ...result.metadata,
          ...conversationResults.metadata,
        },
      };
    } catch (error) {
      console.error('Failed to finalize conversation:', error);
      throw error;
    } finally {
      // Always release lock
      this.conversationManager.releaseLock(sessionId);
    }
  }

  async getConversationStatus(
    sessionId: string,
  ): Promise<{
    sessionId: string;
    status: string;
    turnCount: number;
    lastActivity: number;
    progress: number;
    canFinalize: boolean;
  }> {
    const session = this.conversationManager.getSession(sessionId);
    if (!session) {
      return {
        sessionId,
        status: 'not_found',
        turnCount: 0,
        lastActivity: 0,
        progress: 0,
        canFinalize: false,
      };
    }

    const canFinalize = this.conversationManager.shouldComplete(sessionId);

    return {
      sessionId,
      status: session.status,
      turnCount: session.turns.length,
      lastActivity: session.lastActivity,
      progress: session.analysisProgress.confidenceLevel,
      canFinalize,
    };
  }

  /**
   * Simulate the impact of a proposed code change using What-If analysis
   */
  async simulateChange(
    context: ClaudeCodeContext,
    proposedChange: ProposedChange,
    simulationParameters?: SimulationParameters,
  ): Promise<SimulationResult> {
    try {
      // Create a conversational session for the multi-step analysis
      const sessionId = this.conversationManager.createSession(context);

      // Read all relevant code files
      const codeFiles = await this.codeReader.readCodeFiles(context.focusArea);

      // Also read the files affected by the proposed change
      for (const file of proposedChange.affectedFiles) {
        if (!codeFiles.has(file)) {
          try {
            const content = await this.codeReader.readFile(file);
            codeFiles.set(file, content);
          } catch (error) {
            console.warn(`Could not read affected file ${file}:`, error);
          }
        }
      }

      // Start the three-step comparative simulation
      const result = await this.performComparativeSimulation(
        sessionId,
        context,
        proposedChange,
        codeFiles,
        simulationParameters,
      );

      // Clean up the session
      this.conversationManager.removeSession(sessionId);

      return result;
    } catch (error) {
      console.error('Error in simulateChange:', error);
      
      // Return a high-risk result on error
      return {
        summary: {
          recommendation: 'high_risk_do_not_implement',
          justification: `Failed to simulate change: ${error instanceof Error ? error.message : 'Unknown error'}`,
        },
        findings: [],
      };
    }
  }

  /**
   * Perform the three-step comparative simulation using conversational AI
   */
  private async performComparativeSimulation(
    sessionId: string,
    context: ClaudeCodeContext,
    proposedChange: ProposedChange,
    codeFiles: Map<string, string>,
    parameters?: SimulationParameters,
  ): Promise<SimulationResult> {
    // This is a placeholder - we'll implement the full three-step chain
    // in the next commit after setting up the conversational prompts
    
    // For now, return a basic result
    return {
      summary: {
        recommendation: 'proceed_with_caution',
        justification: 'Simulation not yet fully implemented',
      },
      findings: [],
    };
  }
}