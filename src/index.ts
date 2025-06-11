#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import * as dotenv from 'dotenv';

import { DeepCodeReasonerV2 } from './analyzers/DeepCodeReasonerV2.js';
import type { ClaudeCodeContext, CodeScope } from './models/types.js';
import { ErrorClassifier } from './utils/ErrorClassifier.js';

// Load environment variables
dotenv.config();

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
  console.error('ERROR: GEMINI_API_KEY environment variable is required');
  console.error('Please set GEMINI_API_KEY in your .env file or environment');
  process.exit(1);
}

const server = new Server(
  {
    name: 'deep-code-reasoning-mcp',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

const deepReasoner = new DeepCodeReasonerV2(GEMINI_API_KEY);

const EscalateAnalysisSchema = z.object({
  claude_context: z.object({
    attempted_approaches: z.array(z.string()),
    partial_findings: z.array(z.any()),
    stuck_description: z.string(),
    code_scope: z.object({
      files: z.array(z.string()),
      entry_points: z.array(z.any()).optional(),
      service_names: z.array(z.string()).optional(),
    }),
  }),
  analysis_type: z.enum(['execution_trace', 'cross_system', 'performance', 'hypothesis_test']),
  depth_level: z.number().min(1).max(5),
  time_budget_seconds: z.number().default(60),
});

const TraceExecutionPathSchema = z.object({
  entry_point: z.object({
    file: z.string(),
    line: z.number(),
    function_name: z.string().optional(),
  }),
  max_depth: z.number().default(10),
  include_data_flow: z.boolean().default(true),
});

const HypothesisTestSchema = z.object({
  hypothesis: z.string(),
  code_scope: z.object({
    files: z.array(z.string()),
    entry_points: z.array(z.any()).optional(),
  }),
  test_approach: z.string(),
});

const CrossSystemImpactSchema = z.object({
  change_scope: z.object({
    files: z.array(z.string()),
    service_names: z.array(z.string()).optional(),
  }),
  impact_types: z.array(z.enum(['breaking', 'performance', 'behavioral'])).optional(),
});

const PerformanceBottleneckSchema = z.object({
  code_path: z.object({
    entry_point: z.object({
      file: z.string(),
      line: z.number(),
      function_name: z.string().optional(),
    }),
    suspected_issues: z.array(z.string()).optional(),
  }),
  profile_depth: z.number().min(1).max(5).default(3),
});

const StartConversationSchema = z.object({
  claude_context: z.object({
    attempted_approaches: z.array(z.string()),
    partial_findings: z.array(z.any()),
    stuck_description: z.string(),
    code_scope: z.object({
      files: z.array(z.string()),
      entry_points: z.array(z.any()).optional(),
      service_names: z.array(z.string()).optional(),
    }),
  }),
  analysis_type: z.enum(['execution_trace', 'cross_system', 'performance', 'hypothesis_test']),
  initial_question: z.string().optional(),
});

const ContinueConversationSchema = z.object({
  session_id: z.string(),
  message: z.string(),
  include_code_snippets: z.boolean().optional(),
});

const FinalizeConversationSchema = z.object({
  session_id: z.string(),
  summary_format: z.enum(['detailed', 'concise', 'actionable']).optional(),
});

const GetConversationStatusSchema = z.object({
  session_id: z.string(),
});

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'escalate_analysis',
        description: 'Hand off complex analysis to Gemini when Claude Code hits reasoning limits. Gemini will perform deep semantic analysis beyond syntactic patterns.',
        inputSchema: {
          type: 'object',
          properties: {
            claude_context: {
              type: 'object',
              properties: {
                attempted_approaches: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'What Claude Code already tried',
                },
                partial_findings: {
                  type: 'array',
                  description: 'Any findings Claude Code discovered',
                },
                stuck_description: {
                  type: 'string',
                  description: 'Description of where Claude Code got stuck',
                },
                code_scope: {
                  type: 'object',
                  properties: {
                    files: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Files to analyze',
                    },
                    entry_points: {
                      type: 'array',
                      description: 'Specific functions/methods to start from',
                    },
                    service_names: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Services involved in cross-system analysis',
                    },
                  },
                  required: ['files'],
                },
              },
              required: ['attempted_approaches', 'partial_findings', 'stuck_description', 'code_scope'],
            },
            analysis_type: {
              type: 'string',
              enum: ['execution_trace', 'cross_system', 'performance', 'hypothesis_test'],
              description: 'Type of deep analysis to perform',
            },
            depth_level: {
              type: 'number',
              minimum: 1,
              maximum: 5,
              description: 'How deep to analyze (1=shallow, 5=very deep)',
            },
            time_budget_seconds: {
              type: 'number',
              default: 60,
              description: 'Maximum time for analysis',
            },
          },
          required: ['claude_context', 'analysis_type'],
        },
      },
      {
        name: 'trace_execution_path',
        description: 'Use Gemini to perform deep execution analysis with semantic understanding',
        inputSchema: {
          type: 'object',
          properties: {
            entry_point: {
              type: 'object',
              properties: {
                file: { type: 'string' },
                line: { type: 'number' },
                function_name: { type: 'string' },
              },
              required: ['file', 'line'],
            },
            max_depth: { type: 'number', default: 10 },
            include_data_flow: { type: 'boolean', default: true },
          },
          required: ['entry_point'],
        },
      },
      {
        name: 'hypothesis_test',
        description: 'Use Gemini to test specific theories about code behavior',
        inputSchema: {
          type: 'object',
          properties: {
            hypothesis: { type: 'string' },
            code_scope: {
              type: 'object',
              properties: {
                files: { type: 'array', items: { type: 'string' } },
                entry_points: { type: 'array' },
              },
              required: ['files'],
            },
            test_approach: { type: 'string' },
          },
          required: ['hypothesis', 'code_scope', 'test_approach'],
        },
      },
      {
        name: 'cross_system_impact',
        description: 'Use Gemini to analyze changes across service boundaries',
        inputSchema: {
          type: 'object',
          properties: {
            change_scope: {
              type: 'object',
              properties: {
                files: { type: 'array', items: { type: 'string' } },
                service_names: { type: 'array', items: { type: 'string' } },
              },
              required: ['files'],
            },
            impact_types: {
              type: 'array',
              items: { type: 'string', enum: ['breaking', 'performance', 'behavioral'] },
            },
          },
          required: ['change_scope'],
        },
      },
      {
        name: 'performance_bottleneck',
        description: 'Use Gemini for deep performance analysis with execution modeling',
        inputSchema: {
          type: 'object',
          properties: {
            code_path: {
              type: 'object',
              properties: {
                entry_point: {
                  type: 'object',
                  properties: {
                    file: { type: 'string' },
                    line: { type: 'number' },
                    function_name: { type: 'string' },
                  },
                  required: ['file', 'line'],
                },
                suspected_issues: { type: 'array', items: { type: 'string' } },
              },
              required: ['entry_point'],
            },
            profile_depth: { type: 'number', minimum: 1, maximum: 5, default: 3 },
          },
          required: ['code_path'],
        },
      },
      {
        name: 'start_conversation',
        description: 'Start a conversational analysis session between Claude and Gemini',
        inputSchema: {
          type: 'object',
          properties: {
            claude_context: {
              type: 'object',
              properties: {
                attempted_approaches: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'What Claude Code already tried',
                },
                partial_findings: {
                  type: 'array',
                  description: 'Any findings Claude Code discovered',
                },
                stuck_description: {
                  type: 'string',
                  description: 'Description of where Claude Code got stuck',
                },
                code_scope: {
                  type: 'object',
                  properties: {
                    files: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Files to analyze',
                    },
                    entry_points: {
                      type: 'array',
                      description: 'Specific functions/methods to start from',
                    },
                    service_names: {
                      type: 'array',
                      items: { type: 'string' },
                      description: 'Services involved in cross-system analysis',
                    },
                  },
                  required: ['files'],
                },
              },
              required: ['attempted_approaches', 'partial_findings', 'stuck_description', 'code_scope'],
            },
            analysis_type: {
              type: 'string',
              enum: ['execution_trace', 'cross_system', 'performance', 'hypothesis_test'],
              description: 'Type of deep analysis to perform',
            },
            initial_question: {
              type: 'string',
              description: 'Initial question to start the conversation',
            },
          },
          required: ['claude_context', 'analysis_type'],
        },
      },
      {
        name: 'continue_conversation',
        description: 'Continue an ongoing analysis conversation',
        inputSchema: {
          type: 'object',
          properties: {
            session_id: {
              type: 'string',
              description: 'ID of the conversation session',
            },
            message: {
              type: 'string',
              description: 'Claude\'s response or follow-up question',
            },
            include_code_snippets: {
              type: 'boolean',
              description: 'Whether to include code snippets in response',
            },
          },
          required: ['session_id', 'message'],
        },
      },
      {
        name: 'finalize_conversation',
        description: 'Complete the conversation and get final analysis results',
        inputSchema: {
          type: 'object',
          properties: {
            session_id: {
              type: 'string',
              description: 'ID of the conversation session',
            },
            summary_format: {
              type: 'string',
              enum: ['detailed', 'concise', 'actionable'],
              description: 'Format for the final summary',
            },
          },
          required: ['session_id'],
        },
      },
      {
        name: 'get_conversation_status',
        description: 'Check the status and progress of an ongoing conversation',
        inputSchema: {
          type: 'object',
          properties: {
            session_id: {
              type: 'string',
              description: 'ID of the conversation session',
            },
          },
          required: ['session_id'],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  try {
    const { name, arguments: args } = request.params;

    switch (name) {
      case 'escalate_analysis': {
        const parsed = EscalateAnalysisSchema.parse(args);
        const context: ClaudeCodeContext = {
          attemptedApproaches: parsed.claude_context.attempted_approaches,
          partialFindings: parsed.claude_context.partial_findings,
          stuckPoints: [parsed.claude_context.stuck_description],
          focusArea: parsed.claude_context.code_scope as CodeScope,
          analysisBudgetRemaining: parsed.time_budget_seconds,
        };

        const result = await deepReasoner.escalateFromClaudeCode(
          context,
          parsed.analysis_type,
          parsed.depth_level || 3,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'trace_execution_path': {
        const parsed = TraceExecutionPathSchema.parse(args);
        const result = await deepReasoner.traceExecutionPath(
          parsed.entry_point,
          parsed.max_depth,
          parsed.include_data_flow,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'hypothesis_test': {
        const parsed = HypothesisTestSchema.parse(args);
        const result = await deepReasoner.testHypothesis(
          parsed.hypothesis,
          parsed.code_scope.files,
          parsed.test_approach,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'cross_system_impact': {
        const parsed = CrossSystemImpactSchema.parse(args);
        const result = await deepReasoner.analyzeCrossSystemImpact(
          parsed.change_scope.files,
          parsed.impact_types,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'performance_bottleneck': {
        const parsed = PerformanceBottleneckSchema.parse(args);
        const result = await deepReasoner.analyzePerformance(
          parsed.code_path.entry_point,
          parsed.profile_depth,
          parsed.code_path.suspected_issues,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'start_conversation': {
        const parsed = StartConversationSchema.parse(args);
        const context: ClaudeCodeContext = {
          attemptedApproaches: parsed.claude_context.attempted_approaches,
          partialFindings: parsed.claude_context.partial_findings,
          stuckPoints: [parsed.claude_context.stuck_description],
          focusArea: parsed.claude_context.code_scope as CodeScope,
          analysisBudgetRemaining: 60,
        };

        const result = await deepReasoner.startConversation(
          context,
          parsed.analysis_type,
          parsed.initial_question,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'continue_conversation': {
        const parsed = ContinueConversationSchema.parse(args);
        const result = await deepReasoner.continueConversation(
          parsed.session_id,
          parsed.message,
          parsed.include_code_snippets,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'finalize_conversation': {
        const parsed = FinalizeConversationSchema.parse(args);
        const result = await deepReasoner.finalizeConversation(
          parsed.session_id,
          parsed.summary_format,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'get_conversation_status': {
        const parsed = GetConversationStatusSchema.parse(args);
        const result = await deepReasoner.getConversationStatus(
          parsed.session_id,
        );

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      default:
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Unknown tool: ${name}`,
        );
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new McpError(
        ErrorCode.InvalidParams,
        `Invalid parameters: ${error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ')}`,
      );
    }
    
    // Use ErrorClassifier for consistent error handling
    if (error instanceof Error) {
      const classification = ErrorClassifier.classify(error);
      
      switch (classification.category) {
        case 'session':
          throw new McpError(
            ErrorCode.InvalidRequest,
            classification.description,
          );
          
        case 'api':
          throw new McpError(
            ErrorCode.InternalError,
            classification.description,
          );
          
        case 'filesystem':
          throw new McpError(
            ErrorCode.InvalidRequest,
            classification.description,
          );
          
        default:
          console.error('Unhandled error in request handler:', error);
          throw new McpError(
            ErrorCode.InternalError,
            `Internal error: ${error.message}. Check server logs for details.`,
          );
      }
    }
    
    throw error;
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Deep Code Reasoning MCP server running with Gemini');
  console.error('Using Gemini model: gemini-2.5-pro-preview-05-06');
}

main().catch((error) => {
  console.error('Fatal error in main():', error);
  process.exit(1);
});