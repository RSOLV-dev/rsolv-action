// Java AST Parser for RSOLV RFC-031
// Uses JavaParser to parse Java code and return AST in JSON format via stdin/stdout

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.github.javaparser.Problem;
import com.github.javaparser.ParseResult;
import com.github.javaparser.Position;
import com.github.javaparser.Range;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

public class Parser {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final int TIMEOUT_SECONDS = 30;

    public static void main(String[] args) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            String line;
            while ((line = reader.readLine()) != null) {
                processRequest(line.trim());
                System.out.flush();
            }
        } catch (Exception e) {
            writeErrorResponse("unknown", "IOError", "Failed to read input: " + e.getMessage());
        }
    }

    private static void processRequest(String jsonInput) {
        try {
            // Parse timeout with CompletableFuture
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                try {
                    handleRequest(jsonInput);
                } catch (Exception e) {
                    writeErrorResponse("unknown", e.getClass().getSimpleName(), e.getMessage());
                }
            });

            future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

        } catch (TimeoutException e) {
            writeErrorResponse("unknown", "TimeoutError", "Parser timeout after " + TIMEOUT_SECONDS + " seconds");
        } catch (Exception e) {
            writeErrorResponse("unknown", e.getClass().getSimpleName(), e.getMessage());
        }
    }

    private static void handleRequest(String jsonInput) throws Exception {
        ObjectNode request = (ObjectNode) mapper.readTree(jsonInput);
        String requestId = request.has("id") ? request.get("id").asText() : "unknown";
        String command = request.has("command") ? request.get("command").asText() : "";
        String action = request.has("action") ? request.get("action").asText() : command;

        if ("HEALTH_CHECK".equals(action)) {
            ObjectNode response = mapper.createObjectNode();
            response.put("id", requestId);
            response.put("result", "ok");
            System.out.println(mapper.writeValueAsString(response));
            return;
        }

        long startTime = System.currentTimeMillis();
        String code = "";
        ObjectNode options = mapper.createObjectNode();
        String filename = "<string>";

        if (!"parse".equals(action) && !action.isEmpty()) {
            // Command-based interface
            code = command;
            if (request.has("options")) {
                options = (ObjectNode) request.get("options");
            }
            if (request.has("filename")) {
                filename = request.get("filename").asText();
            }
        } else {
            // Standard parse interface
            if (request.has("code")) {
                code = request.get("code").asText();
            }
            if (request.has("options")) {
                options = (ObjectNode) request.get("options");
            }
            if (request.has("filename")) {
                filename = request.get("filename").asText();
            }
        }

        // Parse Java code
        JavaParser javaParser = new JavaParser();
        ParseResult<CompilationUnit> parseResult = javaParser.parse(code);

        ObjectNode response = mapper.createObjectNode();
        response.put("id", requestId);

        if (parseResult.isSuccessful() && parseResult.getResult().isPresent()) {
            CompilationUnit cu = parseResult.getResult().get();
            ObjectNode astNode = convertToDict(cu);
            
            // Extract security patterns
            ArrayNode securityPatterns = mapper.createArrayNode();
            boolean includeSecurityPatterns = !options.has("include_security_patterns") || 
                                             options.get("include_security_patterns").asBoolean(true);
            
            if (includeSecurityPatterns) {
                findSecurityPatterns(cu, securityPatterns);
            }

            long parseTime = System.currentTimeMillis() - startTime;
            int nodeCount = countNodes(cu);

            response.put("status", "success");
            response.put("success", true);
            response.set("ast", astNode);
            response.set("security_patterns", securityPatterns);

            ObjectNode metadata = mapper.createObjectNode();
            metadata.put("parser_version", "1.0.0");
            metadata.put("language", "java");
            metadata.put("language_version", System.getProperty("java.version"));
            metadata.put("parse_time_ms", parseTime);
            metadata.put("ast_node_count", nodeCount);
            response.set("metadata", metadata);

        } else {
            // Parse failed
            ObjectNode error = mapper.createObjectNode();
            error.put("type", "SyntaxError");
            
            StringBuilder errorMessage = new StringBuilder();
            for (Problem problem : parseResult.getProblems()) {
                if (errorMessage.length() > 0) {
                    errorMessage.append("; ");
                }
                errorMessage.append(problem.getMessage());
            }
            
            error.put("message", errorMessage.toString());
            if (!parseResult.getProblems().isEmpty()) {
                Problem firstProblem = parseResult.getProblems().get(0);
                if (firstProblem.getLocation().isPresent()) {
                    Range range = firstProblem.getLocation().get();
                    error.put("line", range.begin.line);
                    error.put("column", range.begin.column);
                }
            }

            response.put("status", "error");
            response.put("success", false);
            response.set("error", error);
        }

        System.out.println(mapper.writeValueAsString(response));
    }

    private static ObjectNode convertToDict(Node node) {
        ObjectNode result = mapper.createObjectNode();
        result.put("type", node.getClass().getSimpleName());

        // Add location information
        if (node.getRange().isPresent()) {
            Range range = node.getRange().get();
            ObjectNode loc = mapper.createObjectNode();
            
            ObjectNode start = mapper.createObjectNode();
            start.put("line", range.begin.line);
            start.put("column", range.begin.column);
            
            ObjectNode end = mapper.createObjectNode();
            end.put("line", range.end.line);
            end.put("column", range.end.column);
            
            loc.set("start", start);
            loc.set("end", end);
            result.set("_loc", loc);
            
            // Approximate start/end positions (JavaParser doesn't provide exact char positions)
            result.put("_start", (range.begin.line - 1) * 80 + range.begin.column);
            result.put("_end", (range.end.line - 1) * 80 + range.end.column);
        }

        // Process children nodes
        List<Node> children = node.getChildNodes();
        if (!children.isEmpty()) {
            ArrayNode childrenArray = mapper.createArrayNode();
            for (Node child : children) {
                childrenArray.add(convertToDict(child));
            }
            result.set("children", childrenArray);
        }

        // Add node-specific information
        addNodeSpecificInfo(node, result);

        return result;
    }

    private static void addNodeSpecificInfo(Node node, ObjectNode result) {
        // Add specific information based on node type
        if (node instanceof MethodCallExpr) {
            MethodCallExpr methodCall = (MethodCallExpr) node;
            result.put("method_name", methodCall.getNameAsString());
        } else if (node instanceof MethodDeclaration) {
            MethodDeclaration method = (MethodDeclaration) node;
            result.put("method_name", method.getNameAsString());
        } else if (node instanceof ClassOrInterfaceDeclaration) {
            ClassOrInterfaceDeclaration classDecl = (ClassOrInterfaceDeclaration) node;
            result.put("class_name", classDecl.getNameAsString());
            result.put("is_interface", classDecl.isInterface());
        } else if (node instanceof VariableDeclarator) {
            VariableDeclarator var = (VariableDeclarator) node;
            result.put("variable_name", var.getNameAsString());
        }
    }

    private static void findSecurityPatterns(Node node, ArrayNode patterns) {
        // Traverse and find security-relevant patterns
        traverseForSecurityPatterns(node, patterns);
    }

    private static void traverseForSecurityPatterns(Node node, ArrayNode patterns) {
        // Check current node for security patterns
        checkNodeForSecurityPatterns(node, patterns);

        // Recursively check children
        for (Node child : node.getChildNodes()) {
            traverseForSecurityPatterns(child, patterns);
        }
    }

    private static void checkNodeForSecurityPatterns(Node node, ArrayNode patterns) {
        if (node instanceof MethodCallExpr) {
            MethodCallExpr methodCall = (MethodCallExpr) node;
            String methodName = methodCall.getNameAsString();
            
            // Check for dangerous methods
            Set<String> dangerousMethods = Set.of(
                "exec", "getRuntime", "processBuilder", "system",
                "eval", "load", "loadClass", "forName",
                "createStatement", "prepareStatement", "execute", "executeQuery",
                "setProperty", "getProperty"
            );
            
            if (dangerousMethods.contains(methodName)) {
                ObjectNode pattern = mapper.createObjectNode();
                pattern.put("type", "dangerous_method");
                pattern.put("method", methodName);
                addLocationToPattern(node, pattern);
                patterns.add(pattern);
            }
            
            // Check for SQL injection patterns
            if (methodName.matches(".*[Ss]tatement.*|.*[Qq]uery.*|.*[Ee]xecute.*")) {
                ObjectNode pattern = mapper.createObjectNode();
                pattern.put("type", "potential_sql_injection");
                pattern.put("method", methodName);
                addLocationToPattern(node, pattern);
                patterns.add(pattern);
            }
            
        } else if (node instanceof StringLiteralExpr) {
            StringLiteralExpr stringLiteral = (StringLiteralExpr) node;
            String value = stringLiteral.getValue().toLowerCase();
            
            // Check for SQL keywords in strings
            if (value.contains("select ") || value.contains("insert ") || 
                value.contains("update ") || value.contains("delete ")) {
                ObjectNode pattern = mapper.createObjectNode();
                pattern.put("type", "sql_string");
                pattern.put("content", stringLiteral.getValue());
                addLocationToPattern(node, pattern);
                patterns.add(pattern);
            }
            
        } else if (node instanceof ObjectCreationExpr) {
            ObjectCreationExpr objCreation = (ObjectCreationExpr) node;
            String typeName = objCreation.getTypeAsString();
            
            // Check for dangerous object creation
            if (typeName.contains("ProcessBuilder") || typeName.contains("Runtime")) {
                ObjectNode pattern = mapper.createObjectNode();
                pattern.put("type", "process_creation");
                pattern.put("class", typeName);
                addLocationToPattern(node, pattern);
                patterns.add(pattern);
            }
        }
    }

    private static void addLocationToPattern(Node node, ObjectNode pattern) {
        if (node.getRange().isPresent()) {
            Range range = node.getRange().get();
            pattern.put("line", range.begin.line);
            pattern.put("column", range.begin.column);
        } else {
            pattern.put("line", 0);
            pattern.put("column", 0);
        }
    }

    private static int countNodes(Node node) {
        int count = 1; // Count current node
        for (Node child : node.getChildNodes()) {
            count += countNodes(child);
        }
        return count;
    }

    private static void writeErrorResponse(String requestId, String errorType, String message) {
        try {
            ObjectNode response = mapper.createObjectNode();
            response.put("id", requestId);
            response.put("status", "error");
            response.put("success", false);

            ObjectNode error = mapper.createObjectNode();
            error.put("type", errorType);
            error.put("message", message);
            response.set("error", error);

            System.out.println(mapper.writeValueAsString(response));
            System.out.flush();
        } catch (Exception e) {
            System.err.println("Failed to write error response: " + e.getMessage());
        }
    }
}