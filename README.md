[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/haasonsaas-deep-code-reasoning-mcp-badge.png)](https://mseep.ai/app/haasonsaas-deep-code-reasoning-mcp)

# Deep Code Reasoning MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.com)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)

An MCP server that pairs Claude Code with Google's Gemini AI for complementary code analysis. This server enables a multi-model workflow where Claude Code handles tight terminal integration and multi-file refactoring, while Gemini leverages its massive context window (1M tokens) and code execution capabilities for distributed system debugging and long-trace analysis.

## Core Value

Both Claude and Gemini can handle deep semantic reasoning and distributed system bugs. This server enables an intelligent routing strategy where:
- **Claude Code** excels at local-context operations, incremental patches, and CLI-native workflows
- **Gemini 2.5 Pro** shines with huge-context sweeps, synthetic test execution, and analyzing failures that span logs + traces + code

The "escalation" model treats LLMs like heterogeneous microservices - route to the one that's most capable for each sub-task.

## Features

- **Gemini 2.5 Pro Preview**: Uses Google's latest Gemini 2.5 Pro Preview (05-06) model with 1M token context window
- **Conversational Analysis**: NEW! AI-to-AI dialogues between Claude and Gemini for iterative problem-solving
- **Execution Flow Tracing**: Understands data flow and state transformations, not just function calls
- **Cross-System Impact Analysis**: Models how changes propagate across service boundaries
- **Performance Modeling**: Identifies N+1 patterns, memory leaks, and algorithmic bottlenecks
- **Hypothesis Testing**: Tests theories about code behavior with evidence-based validation
- **Long Context Support**: Leverages Gemini 2.5 Pro Preview's 1M token context for analyzing large codebases

## Prerequisites

- Node.js 18 or later
- A Google Cloud account with Gemini API access
- Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)

## Key Dependencies

- **@google/generative-ai**: Google's official SDK for Gemini API integration
- **@modelcontextprotocol/sdk**: MCP protocol implementation for Claude integration
- **zod**: Runtime type validation for tool parameters
- **dotenv**: Environment variable management

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Haasonsaas/deep-code-reasoning-mcp.git
cd deep-code-reasoning-mcp
```

2. Install dependencies:
```bash
npm install
```

3. Set up your Gemini API key:
```bash
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

4. Build the project:
```bash
npm run build
```

## Configuration

### Environment Variables

- `GEMINI_API_KEY` (required): Your Google Gemini API key

### Claude Desktop Configuration

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "deep-code-reasoning": {
      "command": "node",
      "args": ["/path/to/deep-code-reasoning-mcp/dist/index.js"],
      "env": {
        "GEMINI_API_KEY": "your-gemini-api-key"
      }
    }
  }
}
```

## How It Works

1. **Claude Code performs initial analysis** using its strengths in multi-file refactoring and test-driven loops
2. **When beneficial, Claude escalates to this MCP server** - particularly for:
   - Analyzing gigantic log/trace dumps that exceed Claude's context
   - Running iterative hypothesis testing with code execution
   - Correlating failures across many microservices
3. **Server prepares comprehensive context** including code, logs, and traces
4. **Gemini analyzes with its 1M-token context** and visible "thinking" traces
5. **Results returned to Claude Code** for implementation of fixes

## Available Tools

**Note**: The tool parameters use snake_case naming convention and are validated using Zod schemas. The actual implementation provides more detailed type safety than shown in these simplified examples. Full TypeScript type definitions are available in `src/models/types.ts`.

### Conversational Analysis Tools

The server now includes AI-to-AI conversational tools that enable Claude and Gemini to engage in multi-turn dialogues for complex analysis:

#### start_conversation
Initiates a conversational analysis session between Claude and Gemini.

```typescript
{
  claude_context: {
    attempted_approaches: string[];      // What Claude tried
    partial_findings: any[];            // What Claude found
    stuck_description: string;          // Where Claude got stuck
    code_scope: {
      files: string[];                  // Files to analyze
      entry_points?: CodeLocation[];    // Starting points
      service_names?: string[];         // Services involved
    }
  };
  analysis_type: 'execution_trace' | 'cross_system' | 'performance' | 'hypothesis_test';
  initial_question?: string;            // Optional opening question
}
```

#### continue_conversation
Continues an active conversation with Claude's response or follow-up question.

```typescript
{
  session_id: string;                   // Active session ID
  message: string;                      // Claude's message to Gemini
  include_code_snippets?: boolean;      // Enrich with code context
}
```

#### finalize_conversation
Completes the conversation and generates structured analysis results.

```typescript
{
  session_id: string;                   // Active session ID
  summary_format: 'detailed' | 'concise' | 'actionable';
}
```

#### get_conversation_status
Checks the status and progress of an ongoing conversation.

```typescript
{
  session_id: string;                   // Session ID to check
}
```

### Traditional Analysis Tools

#### escalate_analysis
Main tool for handing off complex analysis from Claude Code to Gemini.

```typescript
{
  claude_context: {
    attempted_approaches: string[];      // What Claude tried
    partial_findings: any[];            // What Claude found
    stuck_description: string;          // Where Claude got stuck
    code_scope: {
      files: string[];                  // Files to analyze
      entry_points?: CodeLocation[];    // Starting points (file, line, function_name)
      service_names?: string[];         // Services involved
    }
  };
  analysis_type: 'execution_trace' | 'cross_system' | 'performance' | 'hypothesis_test';
  depth_level: 1-5;                     // Analysis depth
  time_budget_seconds?: number;         // Time limit (default: 60)
}
```

### trace_execution_path
Deep execution analysis with Gemini's semantic understanding.

```typescript
{
  entry_point: {
    file: string;
    line: number;
    function_name?: string;
  };
  max_depth?: number;              // Default: 10
  include_data_flow?: boolean;     // Default: true
}
```

### cross_system_impact
Analyze impacts across service boundaries.

```typescript
{
  change_scope: {
    files: string[];
    service_names?: string[];
  };
  impact_types?: ('breaking' | 'performance' | 'behavioral')[];
}
```

### performance_bottleneck
Deep performance analysis beyond simple profiling.

```typescript
{
  code_path: {
    entry_point: {
      file: string;
      line: number;
      function_name?: string;
    };
    suspected_issues?: string[];
  };
  profile_depth?: 1-5;              // Default: 3
}
```

### hypothesis_test
Test specific theories about code behavior.

```typescript
{
  hypothesis: string;
  code_scope: {
    files: string[];
    entry_points?: CodeLocation[];    // Optional array of {file, line, function_name?}
  };
  test_approach: string;
}
```

## Example Use Cases

### Conversational Analysis Example

When Claude needs deep iterative analysis with Gemini:

```javascript
// 1. Start conversation
const session = await start_conversation({
  claude_context: {
    attempted_approaches: ["Checked for N+1 queries", "Profiled database calls"],
    partial_findings: [{ type: "performance", description: "Multiple DB queries in loop" }],
    stuck_description: "Can't determine if queries are optimizable",
    code_scope: { files: ["src/services/UserService.ts"] }
  },
  analysis_type: "performance",
  initial_question: "Are these queries necessary or can they be batched?"
});

// 2. Continue with follow-ups
const response = await continue_conversation({
  session_id: session.sessionId,
  message: "The queries fetch user preferences. Could we use a join instead?",
  include_code_snippets: true
});

// 3. Finalize when ready
const results = await finalize_conversation({
  session_id: session.sessionId,
  summary_format: "actionable"
});
```

### Case 1: Distributed Trace Analysis

When a failure signature spans multiple services with GB of logs:

```javascript
// Claude Code: Identifies the error pattern and suspicious code sections
// Escalate to Gemini when: Need to correlate 1000s of trace spans across 10+ services
// Gemini: Processes the full trace timeline, identifies the exact race window
```

### Case 2: Performance Regression Hunting

When performance degrades but the cause isn't obvious:

```javascript
// Claude Code: Quick profiling, identifies hot paths
// Escalate to Gemini when: Need to analyze weeks of performance metrics + code changes
// Gemini: Correlates deployment timeline with perf metrics, pinpoints the exact commit
```

### Case 3: Hypothesis-Driven Debugging

When you have theories but need extensive testing:

```javascript
// Claude Code: Forms initial hypotheses based on symptoms
// Escalate to Gemini when: Need to test 20+ scenarios with synthetic data
// Gemini: Uses code execution API to validate each hypothesis systematically
```

## Development

```bash
# Run in development mode
npm run dev

# Run tests
npm test

# Lint code
npm run lint

# Type check
npm run typecheck
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Claude Code    │────▶│  MCP Server      │────▶│  Gemini API    │
│  (Fast, Local, │     │  (Router &       │     │  (1M Context,   │
│   CLI-Native)  │◀────│   Orchestrator)  │◀────│   Code Exec)    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  Code + Logs +   │
                        │  Traces + Tests  │
                        └──────────────────┘
```

## Security Considerations

- **API Key**: Store your Gemini API key securely in environment variables
- **Code Access**: The server reads local files - ensure proper file permissions
- **Data Privacy**: Code is sent to Google's Gemini API - review their data policies

## Troubleshooting

### "GEMINI_API_KEY not found"
- Ensure you've set the `GEMINI_API_KEY` in your `.env` file or environment
- Check that the `.env` file is in the project root

### "File not found" errors
- Verify that file paths passed to the tools are absolute paths
- Check file permissions

### Gemini API errors
- Verify your API key is valid and has appropriate permissions
- Check API quotas and rate limits
- Ensure your Google Cloud project has the Gemini API enabled

### Validation errors
- The server uses Zod for parameter validation
- Ensure all required parameters are provided
- Check that parameter names use snake_case (e.g., `claude_context`, not `claudeContext`)
- Review error messages for specific validation requirements

## Best Practices for Multi-Model Debugging

When debugging distributed systems with this MCP server:

1. **Capture the timeline first** - Use OpenTelemetry/Jaeger traces with request IDs
2. **Start with Claude Code** - Let it handle the initial investigation and quick fixes
3. **Escalate strategically** to Gemini when you need:
   - Analysis of traces spanning 100s of MB
   - Correlation across 10+ services
   - Iterative hypothesis testing with code execution
4. **Combine with traditional tools**:
   - `go test -race`, ThreadSanitizer for race detection
   - rr or JFR for deterministic replay
   - TLA+ or Alloy for formal verification

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Jonathan Haas** - [GitHub Profile](https://github.com/Haasonsaas)

## Acknowledgments

- Built for integration with Anthropic's Claude Code
- Powered by Google's Gemini AI
- Uses the Model Context Protocol (MCP) for communication

## Support

If you encounter any issues or have questions:
- Open an issue on [GitHub Issues](https://github.com/Haasonsaas/deep-code-reasoning-mcp/issues)
- Check the [troubleshooting section](#troubleshooting) above
- Review the [MCP documentation](https://modelcontextprotocol.com)