/**
 * PL/SQL Security Rules Metadata
 * Descriptions and recommendations for PL/SQL security issues detected by ZPA
 */

const plsqlRules = {
  // SQL Injection
  S2077: {
    severity: "critical",
    description:
      "SQL Injection vulnerability detected in dynamic SQL. String concatenation in EXECUTE IMMEDIATE or OPEN FOR statements can allow attackers to manipulate SQL queries.",
    recommendation:
      "Use bind variables instead of string concatenation. Replace dynamic SQL with parameterized queries using the USING clause in EXECUTE IMMEDIATE statements.",
  },

  // Code Quality Issues that can lead to security problems
  EmptyCatch: {
    severity: "medium",
    description:
      "Empty exception handler found. Silently catching exceptions can hide security-relevant errors and make debugging difficult.",
    recommendation:
      "Add proper exception handling with logging or re-raise the exception. Never suppress exceptions without handling them appropriately.",
  },

  MissingExceptionHandler: {
    severity: "medium",
    description:
      "Missing exception handler in PL/SQL block. Unhandled exceptions can expose sensitive error information to attackers.",
    recommendation:
      "Add WHEN OTHERS exception handler to catch unexpected errors and log them appropriately without exposing sensitive details.",
  },

  // Resource Management
  CursorNotClosed: {
    severity: "low",
    description:
      "Cursor is not explicitly closed. Leaving cursors open can lead to resource exhaustion and potential denial of service.",
    recommendation:
      "Always close cursors explicitly in the exception handler or use cursor FOR loops which automatically close cursors.",
  },

  // Transaction Management
  AutonomousTransaction: {
    severity: "medium",
    description:
      "Autonomous transaction detected. Improper use can lead to data inconsistency and bypass security controls.",
    recommendation:
      "Ensure autonomous transactions are necessary and properly handle all exception cases to maintain data integrity.",
  },

  // Custom pattern-detected issues
  "weak-crypto": {
    severity: "high",
    description:
      "Use of deprecated DBMS_OBFUSCATION_TOOLKIT package detected. This package provides weak encryption and is deprecated.",
    recommendation:
      "Replace DBMS_OBFUSCATION_TOOLKIT with DBMS_CRYPTO package which provides stronger cryptographic functions (AES, 3DES, etc).",
  },

  "hardcoded-credential": {
    severity: "critical",
    description:
      "Potential hardcoded credential found in PL/SQL code. Hardcoded passwords can be easily discovered and exploited.",
    recommendation:
      "Store credentials in secure credential stores (Oracle Wallet, Vault) or use database authentication mechanisms. Never hardcode passwords in source code.",
  },

  "privilege-escalation": {
    severity: "medium",
    description:
      "AUTHID DEFINER clause detected. This can allow privilege escalation if not properly secured.",
    recommendation:
      "Use AUTHID CURRENT_USER when possible to run procedures with invoker rights. If DEFINER is necessary, carefully audit all code paths and restrict EXECUTE privileges.",
  },

  // Additional SQL Injection patterns
  "dynamic-sql-concatenation": {
    severity: "critical",
    description:
      "Dynamic SQL with string concatenation detected. This pattern is vulnerable to SQL injection attacks.",
    recommendation:
      "Use bind variables with the USING clause: EXECUTE IMMEDIATE sql_stmt USING bind_var1, bind_var2;",
  },

  // Code Quality - Null Handling
  NvlWithNullParameter: {
    severity: "low",
    description:
      "NVL function called with NULL as the replacement value. This is a logic error as NVL is designed to replace NULL values, but providing NULL as the second parameter makes the function call pointless and may indicate a bug in the logic.",
    recommendation:
      "Remove the redundant NVL call or provide a meaningful non-NULL default value. Review the code logic to ensure proper null handling. If the column can be NULL and this is acceptable, remove the NVL wrapper entirely.",
  },

  // Security - Information Disclosure
  SelectAllColumns: {
    severity: "medium",
    description:
      "SELECT * statement detected. Using SELECT * can lead to information disclosure by retrieving sensitive columns unnecessarily, performance degradation from fetching unneeded data, and maintenance issues when table schema changes. This practice may expose confidential data that should not be accessible in the current context.",
    recommendation:
      "Explicitly specify only the columns needed for the query instead of using SELECT *. This improves performance, security, and maintainability. Example: SELECT column1, column2, column3 FROM table_name. Review data access requirements and implement least privilege principle by only selecting necessary columns.",
  },

  // Transaction Management
  CommitRollback: {
    severity: "medium",
    description:
      "COMMIT or ROLLBACK statement found in a stored procedure or function. Explicit transaction control within procedures can lead to data inconsistency, breaks transaction atomicity, prevents the calling application from controlling transactions, and violates the principle that procedures should not control transaction boundaries. This can cause unexpected behavior where partial changes are committed even when errors occur.",
    recommendation:
      "Remove COMMIT and ROLLBACK statements from stored procedures and functions. Let the calling application control transaction boundaries. If transaction control is necessary, use autonomous transactions with PRAGMA AUTONOMOUS_TRANSACTION, but only when absolutely required. Implement proper exception handling and let exceptions propagate to the caller for transaction management.",
  },

  // Code Quality - Dead Code
  DeadCode: {
    severity: "low",
    description:
      "Unreachable or dead code detected that will never be executed. Dead code can hide bugs, make the codebase harder to maintain, increase complexity, and may indicate incomplete refactoring or logic errors. Removing dead code improves code clarity and reduces maintenance burden.",
    recommendation:
      "Remove all dead code and unreachable statements from the codebase. Review the surrounding logic to ensure no functionality was unintentionally disabled. Use code coverage tools and static analysis to identify and eliminate dead code regularly. If code is being preserved for future use, move it to documentation or version control history instead of keeping it in the active codebase.",
  },

  // Code Quality - Variable Initialization
  VariableInitializationWithFunctionCall: {
    severity: "low",
    description:
      "Variable initialized with a function call in the declaration section. This can lead to unexpected behavior if the function has side effects, raises exceptions during package initialization, or depends on session state. It can also make the code harder to debug and cause initialization order dependencies.",
    recommendation:
      "Move function calls from variable declarations to the executable section or initialization block. Initialize variables with simple literal values or constants in the declaration section. Use the BEGIN block to assign values from function calls, which provides better error handling and makes the initialization sequence explicit and controllable.",
  },

  // Code Quality - Unused Variables
  UnusedVariable: {
    severity: "low",
    description:
      "Variable declared but never used in the code. Unused variables clutter the code, may indicate incomplete implementation or refactoring, can hide bugs where a variable was intended to be used, and make the code harder to maintain and understand.",
    recommendation:
      "Remove all unused variable declarations from the code. Review the logic to ensure the variable was not intended to be used. Use PL/SQL development tools and linters to automatically detect unused variables during development. Keep the codebase clean by removing dead code regularly.",
  },

  // Code Quality - Operator Usage
  InequalityUsage: {
    severity: "low",
    description:
      "Use of deprecated inequality operators (!= or ^=) instead of standard SQL inequality operator. While functionally equivalent, using non-standard operators reduces code readability and portability across different SQL dialects. The standard <> operator is more widely recognized and recommended by Oracle coding standards.",
    recommendation:
      "Replace deprecated inequality operators (!= or ^=) with the standard SQL inequality operator <>. This improves code readability, maintains consistency with SQL standards, and ensures better portability across different database systems. Use code formatting tools to enforce consistent operator usage.",
  },

  // Code Quality - Variable Naming
  VariableHiding: {
    severity: "low",
    description:
      "Local variable hides an outer scope variable with the same name. Variable hiding makes code confusing and error-prone, as it is unclear which variable is being referenced at any given point. This can lead to logic errors where the wrong variable is modified or accessed, making debugging difficult.",
    recommendation:
      "Rename the inner variable to use a different name that does not conflict with outer scope variables. Use meaningful and descriptive variable names that clearly indicate their purpose and scope. Establish naming conventions to prevent variable hiding, such as using prefixes for different scopes.",
  },

  // Code Quality - Control Flow
  CollapsibleIfStatements: {
    severity: "low",
    description:
      "Nested IF statements that can be collapsed into a single IF with combined conditions. Unnecessary nesting reduces code readability, increases complexity, and makes the logic harder to understand and maintain. Collapsing nested IFs simplifies the control flow.",
    recommendation:
      "Combine nested IF statements using AND logic into a single IF statement. Replace nested structure with a single condition using logical operators. This improves readability and reduces code complexity. Use parentheses to group conditions clearly when combining multiple logical operations.",
  },

  // Code Quality - Redundant Logic
  SameBranch: {
    severity: "low",
    description:
      "IF-ELSE or CASE statement with identical code in multiple branches. This is redundant logic that makes code harder to maintain and may indicate a copy-paste error or incomplete implementation. Having the same code in multiple branches serves no purpose and should be refactored.",
    recommendation:
      "Remove the conditional statement entirely and execute the common code unconditionally. If some branches are meant to differ, review the logic to ensure correct implementation. Consolidate duplicate code into a single execution path to improve maintainability and reduce code size.",
  },

  // Code Quality - Unused Parameters
  UnusedParameter: {
    severity: "low",
    description:
      "Parameter declared in procedure or function but never used. Unused parameters clutter the interface, confuse callers about what the function actually needs, and may indicate incomplete implementation or unnecessary API surface.",
    recommendation:
      "Remove unused parameters from the procedure or function signature. If the parameter is part of a required interface or callback signature that cannot be changed, prefix it with an underscore to indicate it is intentionally unused.",
  },

  // Code Quality - Data Types
  CharacterDatatypeUsage: {
    severity: "low",
    description:
      "Use of CHAR datatype instead of VARCHAR2. CHAR is fixed-length and pads values with spaces, which can cause unexpected comparison issues and wastes storage space. VARCHAR2 is preferred for variable-length character data.",
    recommendation:
      "Replace CHAR with VARCHAR2 for variable-length character columns. Only use CHAR for truly fixed-length data where padding behavior is explicitly required. Review string comparisons to avoid issues with trailing spaces.",
  },

  // Code Quality - Parameter Mode
  ExplicitInParameter: {
    severity: "low",
    description:
      "Explicit IN mode specified for parameter when IN is the default. While not incorrect, explicitly specifying the default IN mode is redundant and adds unnecessary verbosity to the code.",
    recommendation:
      "Remove the explicit IN keyword from parameter declarations as it is the default mode. Only explicitly specify OUT or IN OUT modes when needed. This reduces code verbosity while maintaining clarity.",
  },

  // Code Quality - Empty Statements
  UnnecessaryNullStatement: {
    severity: "low",
    description:
      "NULL statement that serves no purpose. While NULL can be useful as a placeholder in exception handlers or to document intentional no-ops, unnecessary NULL statements clutter the code and reduce readability.",
    recommendation:
      "Remove unnecessary NULL statements from the code. If a NULL is used to document intentional no-action, add a comment explaining why. In exception handlers, only use NULL if you intentionally want to suppress the exception.",
  },

  // Code Quality - Empty Blocks
  EmptyBlock: {
    severity: "low",
    description:
      "Empty BEGIN-END block or exception handler. Empty blocks may indicate incomplete implementation, removed code, or unnecessary structure. They reduce code clarity and may hide intended functionality.",
    recommendation:
      "Remove empty blocks entirely or add the missing implementation. If the block is intentionally empty (e.g., to handle an exception by doing nothing), add a comment with NULL statement explaining the intent.",
  },

  // Code Quality - Query Optimization
  UnnecessaryAliasInQuery: {
    severity: "low",
    description:
      "Unnecessary table alias in query where only one table is referenced. While aliases are essential for multi-table queries, using them for single-table queries adds unnecessary verbosity without improving clarity.",
    recommendation:
      "Remove table aliases from single-table queries to improve readability. Only use aliases when joining multiple tables, using subqueries, or when the query genuinely benefits from shorter references.",
  },

  // Syntax Error
  ParsingError: {
    severity: "medium",
    description:
      "PL/SQL syntax error or parsing issue detected. The code contains syntax errors that prevent proper parsing and analysis, which will cause compilation failures and may hide other issues in the code.",
    recommendation:
      "Fix all syntax errors in the code. Use a PL/SQL IDE or compiler to identify and resolve parsing issues. Ensure all statements are properly terminated, keywords are spelled correctly, and structure is valid according to PL/SQL syntax rules.",
  },

  // Code Quality - Duplicate Logic
  IdenticalExpression: {
    severity: "low",
    description:
      "Identical expressions on both sides of a binary operator. This is either redundant code that serves no purpose or a logic error where different expressions were intended. Common cases include x == x, x AND x, or x OR x.",
    recommendation:
      "Review the logic and remove redundant identical expressions. If the same expression on both sides is intentional, simplify the code. If different expressions were intended, fix the logic error to use the correct variables or values.",
  },

  // Code Quality - Duplicate Conditions
  SameCondition: {
    severity: "low",
    description:
      "Duplicate conditions in IF-ELSIF or CASE statements. Having the same condition appear multiple times means some branches will never execute, indicating a logic error or copy-paste mistake. This can hide bugs and make the code behavior unpredictable.",
    recommendation:
      "Remove duplicate conditions and ensure each branch has a unique condition. Review the logic to determine the intended behavior and fix any copy-paste errors. Consolidate branches with identical conditions if they perform the same action.",
  },

  // Error Handling
  QueryWithoutExceptionHandling: {
    severity: "medium",
    description:
      "Database query executed without proper exception handling. Unhandled exceptions from queries can cause procedures to fail unexpectedly, expose error details, or leave transactions in inconsistent states. This is particularly important for NO_DATA_FOUND and TOO_MANY_ROWS exceptions.",
    recommendation:
      "Wrap database queries in BEGIN-END blocks with appropriate exception handlers. Handle NO_DATA_FOUND, TOO_MANY_ROWS, and other expected exceptions explicitly. Log errors appropriately and ensure transactions are properly managed in error cases.",
  },

  // SQL Syntax
  NotASelectedExpression: {
    severity: "medium",
    description:
      "Reference to a column or expression that is not part of the SELECT list in a query. This syntax error occurs when trying to reference columns in ORDER BY, GROUP BY, or WHERE clauses that were not selected, causing query failures.",
    recommendation:
      "Ensure all columns referenced in ORDER BY, GROUP BY, HAVING, or WHERE clauses are either included in the SELECT list or are valid aggregate functions. Add missing columns to the SELECT list or use column aliases appropriately.",
  },

  // SQL Best Practices
  InsertWithoutColumns: {
    severity: "medium",
    description:
      "INSERT statement without explicit column list. This is fragile code that breaks when table structure changes, makes the code harder to understand, and can cause errors if column order changes or new columns are added with NOT NULL constraints.",
    recommendation:
      "Always specify the column list explicitly in INSERT statements: INSERT INTO table (col1, col2, col3) VALUES (val1, val2, val3). This makes the code more maintainable, self-documenting, and resilient to schema changes.",
  },

  // Code Readability
  AddParenthesesInNestedExpression: {
    severity: "low",
    description:
      "Complex expression with mixed operators without parentheses. While operator precedence rules determine evaluation order, explicit parentheses improve readability and prevent logic errors from precedence misunderstandings, especially with AND/OR combinations.",
    recommendation:
      "Add parentheses to clarify evaluation order in complex expressions, especially when mixing AND with OR operators. Use parentheses even when not strictly required to make the intended logic clear and reduce the chance of errors.",
  },

  // SQL Best Practices
  ColumnsShouldHaveTableName: {
    severity: "low",
    description:
      "Column references without table qualifiers in multi-table queries. This reduces query clarity, can cause ambiguity errors when columns exist in multiple tables, and makes maintenance difficult when understanding which table each column comes from.",
    recommendation:
      "Always qualify column names with table names or aliases in queries involving multiple tables: SELECT t1.column1, t2.column2 FROM table1 t1 JOIN table2 t2. This improves readability and prevents ambiguity errors.",
  },

  // Default rule for unmapped issues
  unknown: {
    severity: "info",
    description: "PL/SQL code quality or security issue detected.",
    recommendation:
      "Review the code and apply PL/SQL best practices. Consult Oracle security guidelines for PL/SQL development.",
  },
};

function getPlsqlRuleInfo(ruleId) {
  return plsqlRules[ruleId] || plsqlRules["unknown"];
}

module.exports = {
  plsqlRules,
  getPlsqlRuleInfo,
};
