# What-If Scenario Simulator Examples

The What-If Scenario Simulator allows you to predict the impact of code changes before implementing them. This feature uses AI-powered analysis to compare the current state with a proposed change and identify potential risks.

## Example 1: Changing Retry Logic from Exponential to Linear Backoff

### Scenario
You want to change a retry mechanism from exponential backoff to linear backoff in an API client.

### Request
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "hypothesis_test",
    "arguments": {
      "hypothesis": "Changing from exponential to linear backoff will improve predictability but may cause issues under high load",
      "code_scope": {
        "files": ["src/services/ApiClient.ts", "src/utils/RetryHandler.ts"]
      },
      "test_approach": "Analyze the impact of changing retry delays from exponential (2^n seconds) to linear (n * 2 seconds)",
      "proposed_change": {
        "description": "Replace exponential backoff with linear backoff in retry logic",
        "diff": "--- a/src/utils/RetryHandler.ts\n+++ b/src/utils/RetryHandler.ts\n@@ -15,7 +15,7 @@ export class RetryHandler {\n   private calculateDelay(attemptNumber: number): number {\n-    // Exponential backoff: 2^n seconds\n-    return Math.pow(2, attemptNumber) * 1000;\n+    // Linear backoff: n * 2 seconds\n+    return attemptNumber * 2 * 1000;\n   }\n",
        "affected_files": ["src/utils/RetryHandler.ts"]
      },
      "simulation_parameters": {
        "stress_conditions": ["high_concurrency", "high_error_rate"],
        "target_entry_point": "POST /api/orders"
      }
    }
  }
}
```

### Expected Analysis
The simulator will:
1. Analyze the current exponential backoff behavior
2. Compare it with the proposed linear backoff
3. Identify risks like "thundering herd" under high error rates
4. Provide a recommendation (likely "high_risk_do_not_implement" or "proceed_with_caution")

## Example 2: Adding Caching to a Database Query

### Request
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "hypothesis_test",
    "arguments": {
      "hypothesis": "Adding in-memory caching will reduce database load but may cause stale data issues",
      "code_scope": {
        "files": ["src/repositories/UserRepository.ts", "src/services/UserService.ts"]
      },
      "test_approach": "Analyze the impact of caching user data for 5 minutes",
      "proposed_change": {
        "description": "Add 5-minute in-memory cache for user lookups",
        "diff": "--- a/src/repositories/UserRepository.ts\n+++ b/src/repositories/UserRepository.ts\n@@ -1,10 +1,25 @@\n export class UserRepository {\n+  private cache = new Map<string, { user: User; timestamp: number }>();\n+  private CACHE_TTL = 5 * 60 * 1000; // 5 minutes\n+\n   async findById(id: string): Promise<User | null> {\n+    // Check cache first\n+    const cached = this.cache.get(id);\n+    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {\n+      return cached.user;\n+    }\n+\n     const user = await db.query('SELECT * FROM users WHERE id = ?', [id]);\n-    return user;\n+    \n+    // Cache the result\n+    if (user) {\n+      this.cache.set(id, { user, timestamp: Date.now() });\n+    }\n+    \n+    return user;\n   }\n",
        "affected_files": ["src/repositories/UserRepository.ts"]
      },
      "simulation_parameters": {
        "stress_conditions": ["high_concurrency"],
        "target_entry_point": "GET /api/users/:id"
      }
    }
  }
}
```

### Expected Analysis
The simulator will identify:
- Performance improvements under normal load
- Potential memory growth issues
- Data consistency risks
- Need for cache invalidation strategy

## Example 3: Changing Error Handling Strategy

### Request
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "hypothesis_test",
    "arguments": {
      "hypothesis": "Switching from throwing exceptions to returning error objects will improve error handling but may break existing callers",
      "code_scope": {
        "files": ["src/services/PaymentService.ts", "src/controllers/PaymentController.ts"]
      },
      "test_approach": "Analyze the impact of changing error handling from exceptions to Result<T, Error> pattern",
      "proposed_change": {
        "description": "Replace exception throwing with Result pattern for better error handling",
        "diff": "--- a/src/services/PaymentService.ts\n+++ b/src/services/PaymentService.ts\n@@ -10,12 +10,16 @@ export class PaymentService {\n-  async processPayment(amount: number, cardToken: string): Promise<PaymentResult> {\n+  async processPayment(amount: number, cardToken: string): Promise<Result<PaymentResult, PaymentError>> {\n     if (amount <= 0) {\n-      throw new Error('Invalid amount');\n+      return { success: false, error: new PaymentError('INVALID_AMOUNT', 'Amount must be positive') };\n     }\n \n     try {\n       const result = await this.gateway.charge(amount, cardToken);\n-      return result;\n+      return { success: true, data: result };\n     } catch (error) {\n-      throw new PaymentError('Payment processing failed', error);\n+      return { \n+        success: false, \n+        error: new PaymentError('GATEWAY_ERROR', error.message) \n+      };\n     }\n",
        "affected_files": ["src/services/PaymentService.ts"]
      }
    }
  }
}
```

### Expected Analysis
The simulator will flag:
- Breaking changes for all callers
- Need to update error handling throughout the codebase
- Improved error transparency but high implementation risk

## Response Format

The simulator returns a `SimulationResult` with:
- `summary`: Overall recommendation and justification
- `findings`: Specific risks identified with evidence
- `impactComparison`: Before/after analysis of execution paths and performance
- `systemImpact`: Effects on other services or components

Example response structure:
```json
{
  "summary": {
    "recommendation": "high_risk_do_not_implement",
    "justification": "Linear backoff creates thundering herd effect under high error rates"
  },
  "findings": [
    {
      "riskLevel": "critical",
      "findingType": "emergent_instability",
      "description": "Under high error rates, linear backoff causes synchronized retry storms",
      "evidence": {
        "before": "Exponential backoff naturally spreads retries over time",
        "after": "Linear backoff causes all clients to retry nearly simultaneously"
      },
      "location": {
        "file": "src/utils/RetryHandler.ts",
        "line": 17
      }
    }
  ]
}
```