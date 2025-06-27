// Go AST Parser for RSOLV RFC-031
// Uses go/parser and go/ast to parse Go code and return AST in JSON format via stdin/stdout

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type Request struct {
	ID       string                 `json:"id"`
	Command  string                 `json:"command"`
	Action   string                 `json:"action"`
	Code     string                 `json:"code"`
	Options  map[string]interface{} `json:"options"`
	Filename string                 `json:"filename"`
}

type Response struct {
	ID               string                 `json:"id"`
	Status           string                 `json:"status"`
	Success          bool                   `json:"success"`
	AST              interface{}            `json:"ast,omitempty"`
	SecurityPatterns []SecurityPattern      `json:"security_patterns,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
	Error            *ErrorInfo             `json:"error,omitempty"`
}

type ErrorInfo struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

type SecurityPattern struct {
	Type     string `json:"type"`
	Function string `json:"function,omitempty"`
	Method   string `json:"method,omitempty"`
	Package  string `json:"package,omitempty"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

type NodeData struct {
	Type     string                 `json:"type"`
	Loc      *LocationInfo          `json:"_loc,omitempty"`
	Start    int                    `json:"_start,omitempty"`
	End      int                    `json:"_end,omitempty"`
	Children map[string]interface{} `json:"children,omitempty"`
}

type LocationInfo struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

func main() {
	// Set up signal handler for timeout
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGALRM, syscall.SIGTERM, syscall.SIGINT)
	
	go func() {
		<-sigChan
		errorResponse := Response{
			ID:      "unknown",
			Status:  "error",
			Success: false,
			Error: &ErrorInfo{
				Type:    "TimeoutError",
				Message: "Parser timeout after 30 seconds",
			},
		}
		json.NewEncoder(os.Stdout).Encode(errorResponse)
		os.Exit(1)
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			processRequest(line)
		}
	}
}

func processRequest(jsonInput string) {
	var request Request
	if err := json.Unmarshal([]byte(jsonInput), &request); err != nil {
		writeErrorResponse("unknown", "JSONParseError", fmt.Sprintf("Invalid JSON: %v", err))
		return
	}

	if request.Action == "HEALTH_CHECK" || request.Command == "HEALTH_CHECK" {
		response := Response{
			ID:     request.ID,
			Status: "ok",
		}
		json.NewEncoder(os.Stdout).Encode(response)
		return
	}

	startTime := time.Now()
	
	// Get code from request
	code := request.Code
	if code == "" && request.Command != "" {
		code = request.Command
	}
	
	filename := request.Filename
	if filename == "" {
		filename = "<string>"
	}

	// Parse Go code
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, code, parser.ParseComments)
	
	if err != nil {
		// Handle parse errors
		var errorInfo ErrorInfo
		errorInfo.Type = "SyntaxError"
		errorInfo.Message = err.Error()
		
		// Try to extract line/column information
		if list, ok := err.(scanner.ErrorList); ok && len(list) > 0 {
			errorInfo.Line = list[0].Pos.Line
			errorInfo.Column = list[0].Pos.Column
		}
		
		response := Response{
			ID:      request.ID,
			Status:  "error",
			Success: false,
			Error:   &errorInfo,
		}
		json.NewEncoder(os.Stdout).Encode(response)
		return
	}

	// Convert AST to JSON-serializable format
	astData := convertASTNode(file, fset)
	
	// Find security patterns
	var securityPatterns []SecurityPattern
	includeSecurityPatterns := true
	if val, exists := request.Options["include_security_patterns"]; exists {
		if boolVal, ok := val.(bool); ok {
			includeSecurityPatterns = boolVal
		}
	}
	
	if includeSecurityPatterns {
		securityPatterns = findSecurityPatterns(file, fset)
	}

	parseTime := time.Since(startTime)
	nodeCount := countNodes(file)

	// Create response
	response := Response{
		ID:               request.ID,
		Status:           "success",
		Success:          true,
		AST:              astData,
		SecurityPatterns: securityPatterns,
		Metadata: map[string]interface{}{
			"parser_version":   "1.0.0",
			"language":         "go",
			"language_version": runtime.Version(),
			"parse_time_ms":    int(parseTime.Nanoseconds() / 1000000),
			"ast_node_count":   nodeCount,
		},
	}

	json.NewEncoder(os.Stdout).Encode(response)
}

func convertASTNode(node ast.Node, fset *token.FileSet) interface{} {
	if node == nil {
		return nil
	}

	nodeType := reflect.TypeOf(node)
	nodeValue := reflect.ValueOf(node)
	
	// Handle pointer types
	if nodeType.Kind() == reflect.Ptr {
		if nodeValue.IsNil() {
			return nil
		}
		nodeType = nodeType.Elem()
		nodeValue = nodeValue.Elem()
	}

	result := NodeData{
		Type: nodeType.Name(),
	}

	// Add location information
	if pos := node.Pos(); pos.IsValid() {
		start := fset.Position(pos)
		end := fset.Position(node.End())
		
		result.Loc = &LocationInfo{
			Start: Position{Line: start.Line, Column: start.Column},
			End:   Position{Line: end.Line, Column: end.Column},
		}
		result.Start = int(pos)
		result.End = int(node.End())
	}

	// Process fields
	children := make(map[string]interface{})
	
	for i := 0; i < nodeType.NumField(); i++ {
		field := nodeType.Field(i)
		fieldValue := nodeValue.Field(i)
		
		// Skip unexported fields
		if !fieldValue.CanInterface() {
			continue
		}
		
		fieldName := field.Name
		value := fieldValue.Interface()
		
		// Convert different types
		switch v := value.(type) {
		case ast.Node:
			children[fieldName] = convertASTNode(v, fset)
		case []ast.Node:
			var nodes []interface{}
			for _, n := range v {
				nodes = append(nodes, convertASTNode(n, fset))
			}
			children[fieldName] = nodes
		case []ast.Stmt:
			var stmts []interface{}
			for _, stmt := range v {
				stmts = append(stmts, convertASTNode(stmt, fset))
			}
			children[fieldName] = stmts
		case []ast.Expr:
			var exprs []interface{}
			for _, expr := range v {
				exprs = append(exprs, convertASTNode(expr, fset))
			}
			children[fieldName] = exprs
		case []*ast.Field:
			var fields []interface{}
			for _, f := range v {
				fields = append(fields, convertASTNode(f, fset))
			}
			children[fieldName] = fields
		case token.Pos:
			if v.IsValid() {
				pos := fset.Position(v)
				children[fieldName] = map[string]int{
					"line":   pos.Line,
					"column": pos.Column,
				}
			}
		case token.Token:
			children[fieldName] = v.String()
		case string, int, bool:
			children[fieldName] = v
		default:
			// Handle slice types using reflection
			if fieldValue.Kind() == reflect.Slice {
				var items []interface{}
				for j := 0; j < fieldValue.Len(); j++ {
					item := fieldValue.Index(j).Interface()
					if astNode, ok := item.(ast.Node); ok {
						items = append(items, convertASTNode(astNode, fset))
					} else {
						items = append(items, item)
					}
				}
				children[fieldName] = items
			} else if astNode, ok := value.(ast.Node); ok {
				children[fieldName] = convertASTNode(astNode, fset)
			} else {
				children[fieldName] = value
			}
		}
	}
	
	if len(children) > 0 {
		result.Children = children
	}

	return result
}

func findSecurityPatterns(file *ast.File, fset *token.FileSet) []SecurityPattern {
	var patterns []SecurityPattern
	
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// Function calls
			if ident, ok := node.Fun.(*ast.Ident); ok {
				funcName := ident.Name
				
				// Check for dangerous functions
				dangerousFunctions := []string{
					"exec", "system", "eval", "os.Execute",
					"os.StartProcess", "syscall.Exec", "syscall.ForkExec",
					"ioutil.WriteFile", "os.WriteFile", "os.Create",
				}
				
				for _, dangerous := range dangerousFunctions {
					if funcName == dangerous {
						pos := fset.Position(node.Pos())
						patterns = append(patterns, SecurityPattern{
							Type:     "dangerous_function",
							Function: funcName,
							Line:     pos.Line,
							Column:   pos.Column,
						})
						break
					}
				}
			}
			
			// Method calls (package.function)
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					methodName := sel.Sel.Name
					packageName := pkg.Name
					
					// Check for dangerous package methods
					if packageName == "os" && (methodName == "Exec" || methodName == "StartProcess") {
						pos := fset.Position(node.Pos())
						patterns = append(patterns, SecurityPattern{
							Type:    "process_execution",
							Package: packageName,
							Method:  methodName,
							Line:    pos.Line,
							Column:  pos.Column,
						})
					}
					
					if packageName == "sql" || packageName == "database" {
						pos := fset.Position(node.Pos())
						patterns = append(patterns, SecurityPattern{
							Type:    "potential_sql_injection",
							Package: packageName,
							Method:  methodName,
							Line:    pos.Line,
							Column:  pos.Column,
						})
					}
				}
			}
			
		case *ast.BasicLit:
			// String literals that might contain SQL
			if node.Kind == token.STRING {
				value := strings.ToLower(node.Value)
				if strings.Contains(value, "select ") || strings.Contains(value, "insert ") ||
				   strings.Contains(value, "update ") || strings.Contains(value, "delete ") {
					pos := fset.Position(node.Pos())
					patterns = append(patterns, SecurityPattern{
						Type:   "sql_string",
						Line:   pos.Line,
						Column: pos.Column,
					})
				}
			}
		}
		return true
	})
	
	return patterns
}

func countNodes(node ast.Node) int {
	count := 0
	ast.Inspect(node, func(n ast.Node) bool {
		if n != nil {
			count++
		}
		return true
	})
	return count
}

func writeErrorResponse(requestID, errorType, message string) {
	response := Response{
		ID:      requestID,
		Status:  "error",
		Success: false,
		Error: &ErrorInfo{
			Type:    errorType,
			Message: message,
		},
	}
	json.NewEncoder(os.Stdout).Encode(response)
}