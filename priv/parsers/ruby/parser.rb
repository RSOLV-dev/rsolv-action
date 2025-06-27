#!/usr/bin/env ruby
# Ruby AST Parser for RSOLV RFC-031
# Uses Ruby's built-in AST parser to parse Ruby code and returns AST in JSON format via stdin/stdout

# Change to the parser directory to find Gemfile
Dir.chdir(File.dirname(__FILE__))

require 'bundler/setup'
require 'json'
require 'parser/current'
require 'timeout'

# Set up signal handler for timeout
Signal.trap('ALRM') do
  error_response = {
    'status' => 'error',
    'error' => {
      'type' => 'TimeoutError',
      'message' => 'Parser timeout after 30 seconds'
    }
  }
  puts JSON.generate(error_response)
  STDOUT.flush
  exit(1)
end

def node_to_dict(node)
  # Convert Parser::AST::Node to hash format with circular reference handling
  return nil if node.nil?
  return node unless node.is_a?(Parser::AST::Node)
  
  result = {
    'type' => node.type.to_s
  }
  
  # Add location info if available
  if node.loc && node.loc.expression
    result['_loc'] = {
      'start' => {
        'line' => node.loc.expression.line,
        'column' => node.loc.expression.column
      },
      'end' => {
        'line' => node.loc.expression.last_line,
        'column' => node.loc.expression.last_column
      }
    }
    
    result['_start'] = node.loc.expression.begin_pos
    result['_end'] = node.loc.expression.end_pos
  end
  
  # Process children
  if node.children && !node.children.empty?
    result['children'] = node.children.map do |child|
      if child.is_a?(Parser::AST::Node)
        node_to_dict(child)
      elsif child.is_a?(Array)
        child.map { |item| node_to_dict(item) }
      else
        child
      end
    end
  end
  
  result
end

def find_security_patterns(ast)
  # Extract security-relevant patterns from Ruby AST
  patterns = []
  
  def traverse_node(node, patterns)
    return unless node.is_a?(Parser::AST::Node)
    
    case node.type
    when :send
      # Method calls - check for dangerous methods
      receiver, method_name, *args = node.children
      
      if method_name
        method_str = method_name.to_s
        
        # Common dangerous methods
        dangerous_methods = %w[
          eval exec system ` shell_escape
          instance_eval class_eval module_eval
          const_get const_set remove_const
          send __send__ public_send
          html_safe raw
        ]
        
        if dangerous_methods.include?(method_str)
          patterns << {
            'type' => 'dangerous_method',
            'method' => method_str,
            'line' => node.loc && node.loc.expression ? node.loc.expression.line : 0,
            'column' => node.loc && node.loc.expression ? node.loc.expression.column : 0
          }
        end
        
        # SQL injection patterns
        if method_str.match?(/^(find|where|execute|query)$/) && args.any?
          patterns << {
            'type' => 'potential_sql_injection',
            'method' => method_str,
            'line' => node.loc && node.loc.expression ? node.loc.expression.line : 0,
            'column' => node.loc && node.loc.expression ? node.loc.expression.column : 0
          }
        end
        
        # HTML output methods
        if method_str.match?(/^(html_safe|raw)$/)
          patterns << {
            'type' => 'html_output',
            'method' => method_str,
            'line' => node.loc && node.loc.expression ? node.loc.expression.line : 0,
            'column' => node.loc && node.loc.expression ? node.loc.expression.column : 0
          }
        end
      end
      
    when :dstr, :xstr
      # String interpolation and command execution
      patterns << {
        'type' => node.type == :dstr ? 'string_interpolation' : 'command_execution',
        'line' => node.loc ? node.loc.line : 0,
        'column' => node.loc ? node.loc.column : 0
      }
      
    when :const
      # Constant access - check for dangerous constants
      const_name = node.children.last
      if const_name && const_name.to_s.match?(/^(Kernel|Object|BasicObject)$/)
        patterns << {
          'type' => 'dangerous_constant',
          'constant' => const_name.to_s,
          'line' => node.loc ? node.loc.line : 0,
          'column' => node.loc ? node.loc.column : 0
        }
      end
    end
    
    # Recursively traverse children
    node.children.each do |child|
      traverse_node(child, patterns) if child.is_a?(Parser::AST::Node)
    end
  end
  
  traverse_node(ast, patterns)
  patterns
end

def main
  # Main parser loop - reads JSON requests from stdin, writes responses to stdout
  STDOUT.sync = true
  
  while line = STDIN.gets
    begin
      # Set 30-second timeout for each request
      Timeout::timeout(30) do
        request = JSON.parse(line.strip)
        request_id = request['id'] || 'unknown'
        command = request['command'] || ''
        action = request['action'] || command # Support both formats
        
        if action == 'HEALTH_CHECK'
          response = {
            'id' => request_id,
            'result' => 'ok'
          }
        elsif !action.empty? && action != 'parse'
          # Handle command-based interface (for compatibility with PortWorker)
          start_time = Time.now
          code = command # Treat command as code to parse
          options = request['options'] || {}
          filename = request['filename'] || '<string>'
          
          # Parse the Ruby code
          parser = Parser::CurrentRuby.new
          parser.diagnostics.consumer = nil # Suppress warnings to stderr
          
          buffer = Parser::Source::Buffer.new(filename)
          buffer.source = code
          ast = parser.parse(buffer)
          
          # Convert AST to dictionary
          ast_dict = node_to_dict(ast)
          
          # Extract security patterns if requested
          security_patterns = []
          if options['include_security_patterns'] != false
            security_patterns = find_security_patterns(ast)
          end
          
          parse_time_ms = ((Time.now - start_time) * 1000).to_i
          
          # Count nodes by traversing AST
          node_count = 0
          count_nodes = lambda do |node|
            if node.is_a?(Parser::AST::Node)
              node_count += 1
              node.children.each { |child| count_nodes.call(child) }
            elsif node.is_a?(Array)
              node.each { |item| count_nodes.call(item) }
            end
          end
          count_nodes.call(ast)
          
          response = {
            'id' => request_id,
            'status' => 'success',
            'success' => true,
            'ast' => ast_dict,
            'security_patterns' => security_patterns,
            'metadata' => {
              'parser_version' => '1.0.0',
              'language' => 'ruby',
              'language_version' => RUBY_VERSION,
              'parse_time_ms' => parse_time_ms,
              'ast_node_count' => node_count
            }
          }
        elsif action == 'parse' || action.empty?
          start_time = Time.now
          code = request['code'] || ''
          options = request['options'] || {}
          filename = request['filename'] || '<string>'
          
          # Parse the Ruby code
          parser = Parser::CurrentRuby.new
          parser.diagnostics.consumer = nil # Suppress warnings to stderr
          
          buffer = Parser::Source::Buffer.new(filename)
          buffer.source = code
          ast = parser.parse(buffer)
          
          # Convert AST to dictionary
          ast_dict = node_to_dict(ast)
          
          # Extract security patterns if requested
          security_patterns = []
          if options['include_security_patterns'] != false
            security_patterns = find_security_patterns(ast)
          end
          
          parse_time_ms = ((Time.now - start_time) * 1000).to_i
          
          # Count nodes
          node_count = 0
          count_nodes = lambda do |node|
            if node.is_a?(Parser::AST::Node)
              node_count += 1
              node.children.each { |child| count_nodes.call(child) }
            elsif node.is_a?(Array)
              node.each { |item| count_nodes.call(item) }
            end
          end
          count_nodes.call(ast)
          
          response = {
            'id' => request_id,
            'status' => 'success',
            'ast' => ast_dict,
            'security_patterns' => security_patterns,
            'metadata' => {
              'parser_version' => '1.0.0',
              'language' => 'ruby',
              'language_version' => RUBY_VERSION,
              'parse_time_ms' => parse_time_ms,
              'ast_node_count' => node_count
            }
          }
        else
          response = {
            'id' => request_id,
            'status' => 'error',
            'error' => {
              'type' => 'InvalidAction',
              'message' => "Unknown action: #{action}"
            }
          }
        end
        
        puts JSON.generate(response)
        STDOUT.flush
      end
      
    rescue Timeout::Error
      response = {
        'id' => (request && request['id']) || 'unknown',
        'status' => 'error',
        'success' => false,
        'error' => {
          'type' => 'TimeoutError',
          'message' => 'Parser timeout after 30 seconds'
        }
      }
      puts JSON.generate(response)
      STDOUT.flush
      
    rescue Parser::SyntaxError => e
      request_id = 'unknown'
      begin
        request = JSON.parse(line.strip) if line
        request_id = request['id'] if request
      rescue
        # Ignore JSON parse errors for request ID extraction
      end
      
      response = {
        'id' => request_id,
        'status' => 'error',
        'success' => false,
        'error' => {
          'type' => 'SyntaxError',
          'message' => e.message,
          'line' => e.diagnostic && e.diagnostic.location ? e.diagnostic.location.line : nil,
          'column' => e.diagnostic && e.diagnostic.location ? e.diagnostic.location.column : nil
        }
      }
      puts JSON.generate(response)
      STDOUT.flush
      
    rescue JSON::ParserError => e
      response = {
        'id' => 'unknown',
        'status' => 'error',
        'success' => false,
        'error' => {
          'type' => 'JSONParserError',
          'message' => "Invalid JSON: #{e.message}"
        }
      }
      puts JSON.generate(response)
      STDOUT.flush
      
    rescue => e
      request_id = 'unknown'
      begin
        request = JSON.parse(line.strip) if line
        request_id = request['id'] if request
      rescue
        # Ignore errors for request ID extraction
      end
      
      response = {
        'id' => request_id,
        'status' => 'error',
        'success' => false,
        'error' => {
          'type' => e.class.name,
          'message' => e.message
        }
      }
      puts JSON.generate(response)
      STDOUT.flush
    end
  end
end

if __FILE__ == $0
  main
end