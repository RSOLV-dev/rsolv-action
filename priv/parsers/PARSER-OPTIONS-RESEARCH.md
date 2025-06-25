# Language Parser Options Research

This document evaluates parser options for each target language in RFC-031.

## Evaluation Criteria

1. **AST Quality**: Completeness and accuracy of AST representation
2. **Maintenance**: Active development and community support
3. **Performance**: Parse speed for typical files
4. **Integration**: Ease of use from command line / Port
5. **Security Features**: Relevant security-focused AST nodes
6. **Version Support**: Language version compatibility

## Python

### Option 1: Built-in `ast` module ✅ **RECOMMENDED**
- **Pros**: 
  - Part of Python standard library (no deps)
  - Official Python AST format
  - Supports all Python features including type hints
  - Well-documented
- **Cons**: 
  - Python-specific (not cross-language)
- **Version Support**: Python 2.7+ and 3.x
- **Example Usage**:
  ```python
  import ast
  tree = ast.parse(source_code)
  ```

### Option 2: `parso`
- **Pros**: Error recovery, used by Jedi
- **Cons**: External dependency, similar to ast
- **Use Case**: Better for IDE features than security

### Decision: Use built-in `ast` module

## Ruby

### Option 1: `parser` gem ✅ **RECOMMENDED**
- **Pros**:
  - Most popular Ruby parser
  - Supports all Ruby versions
  - Rich AST with location info
  - Used by RuboCop
- **Cons**: 
  - Requires gem installation
- **Version Support**: Ruby 1.8 through 3.x
- **Install**: `gem install parser`
- **Example Usage**:
  ```ruby
  require 'parser/current'
  ast = Parser::CurrentRuby.parse(source_code)
  ```

### Option 2: `ruby_parser`
- **Pros**: Pure Ruby implementation
- **Cons**: Less maintained, missing newer features

### Decision: Use `parser` gem

## PHP

### Option 1: PHP-Parser (nikic) ✅ **RECOMMENDED**
- **Pros**:
  - De facto standard PHP parser
  - Excellent AST representation
  - Supports PHP 5.2 through 8.x
  - Used by PHPStan, Psalm
- **Cons**: 
  - Requires Composer
- **Version Support**: PHP 5.2 - 8.3
- **Install**: `composer require nikic/php-parser`
- **Example Usage**:
  ```php
  $parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
  $ast = $parser->parse($code);
  ```

### Option 2: Microsoft's Tolerant PHP Parser
- **Pros**: Better error recovery
- **Cons**: Less mature, smaller community

### Decision: Use nikic/PHP-Parser

## Java

### Option 1: JavaParser ✅ **RECOMMENDED**
- **Pros**:
  - Popular, well-maintained
  - Good API design
  - Supports Java 1.0 - 21
  - Symbol resolution capabilities
- **Cons**: 
  - Requires JVM
- **Version Support**: Java 1.0 - 21
- **Install**: Download JAR from Maven Central
- **Example Usage**:
  ```java
  CompilationUnit cu = StaticJavaParser.parse(code);
  ```

### Option 2: Eclipse JDT Core
- **Pros**: Very mature, used by Eclipse IDE
- **Cons**: Heavier weight, complex API

### Option 3: Spoon
- **Pros**: Analysis-focused
- **Cons**: Overkill for our needs

### Decision: Use JavaParser

## Go

### Option 1: Built-in `go/parser` ✅ **RECOMMENDED**
- **Pros**:
  - Part of Go standard library
  - Official Go AST format
  - Fast and reliable
  - No dependencies
- **Cons**: 
  - Basic compared to other options
- **Version Support**: All Go versions
- **Example Usage**:
  ```go
  fset := token.NewFileSet()
  node, _ := parser.ParseFile(fset, "", src, 0)
  ```

### Option 2: Tools from `golang.org/x/tools`
- **Pros**: Additional analysis tools
- **Cons**: External dependency for basic parsing

### Decision: Use built-in `go/parser`

## JavaScript/TypeScript

### Current: Babel (in TypeScript client)
- Keep using existing implementation
- Already handles JS/TS well
- Consider moving to server-side later

## C# (Future)

### Option 1: Roslyn
- **Pros**: Official Microsoft compiler
- **Cons**: Heavy, .NET dependency

### Option 2: Tree-sitter-c-sharp
- **Pros**: Lightweight
- **Cons**: Less semantic info

## Rust (Future)

### Option 1: `syn`
- **Pros**: De facto standard
- **Cons**: Rust toolchain required

### Option 2: Tree-sitter-rust
- **Pros**: Consistent with other tree-sitter parsers
- **Cons**: Less Rust-specific features

## Summary Table

| Language | Parser | Dependencies | Version Support | Install Command |
|----------|--------|--------------|-----------------|-----------------|
| Python | ast (built-in) | None | 2.7+, 3.x | N/A |
| Ruby | parser gem | RubyGems | 1.8 - 3.x | `gem install parser` |
| PHP | PHP-Parser | Composer | 5.2 - 8.3 | `composer require nikic/php-parser` |
| Java | JavaParser | JVM | 1.0 - 21 | Download JAR |
| Go | go/parser | None | All | N/A |

## Security-Relevant AST Nodes

### Common Patterns to Detect
1. **String Concatenation**: Building queries/commands with user input
2. **Function Calls**: Dangerous functions (exec, eval, system)
3. **Variable Usage**: Tracking tainted data flow
4. **Control Flow**: Understanding code paths
5. **Method Invocations**: Database queries, file operations

### Language-Specific Concerns
- **Python**: f-strings, %-formatting, .format()
- **Ruby**: String interpolation, backticks
- **PHP**: Superglobals ($_GET, $_POST)
- **Java**: PreparedStatement vs Statement
- **Go**: fmt.Sprintf, os/exec usage

## Implementation Notes

1. Each parser should output normalized AST format
2. Include source location information for accurate reporting
3. Handle syntax errors gracefully
4. Support incremental parsing where possible
5. Consider memory limits for large files

## Next Steps

1. Create parser wrapper scripts for each language
2. Define common AST format for cross-language analysis
3. Build test suite with security-focused examples
4. Benchmark parsing performance