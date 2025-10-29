#!/usr/bin/env ruby
# encoding: UTF-8
# frozen_string_literal: true

# Ruby AST Parser for RSOLV RFC-031
# Uses Ruby's built-in AST parser to parse Ruby code and returns AST in JSON format via stdin/stdout

# Set encoding for STDIN/STDOUT to UTF-8
Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8
STDIN.set_encoding(Encoding::UTF_8)
STDOUT.set_encoding(Encoding::UTF_8)

# Try to use bundler if available, otherwise just require gems directly
begin
  Dir.chdir(File.dirname(__FILE__))
  require 'bundler/setup'
rescue LoadError
  # Bundler not available, gems should be installed globally
end

require 'json'
# Use Prism directly for better error detection and unicode handling
require 'prism'
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
  # Convert Prism::Node to hash format with circular reference handling
  return nil if node.nil?

  # Handle Prism nodes
  if node.respond_to?(:type)
    # Strip _node suffix from Prism types for compatibility with old Parser gem format
    type_str = node.type.to_s.sub(/_node$/, '')
    result = {
      'type' => type_str
    }

    # Add location info if available
    if node.respond_to?(:location) && node.location
      loc = node.location
      result['_loc'] = {
        'start' => {
          'line' => loc.start_line,
          'column' => loc.start_column
        },
        'end' => {
          'line' => loc.end_line,
          'column' => loc.end_column
        }
      }
      result['_start'] = loc.start_offset
      result['_end'] = loc.end_offset
    end

    # Process child nodes
    children = []
    if node.respond_to?(:child_nodes)
      children = node.child_nodes.compact.map { |child| node_to_dict(child) }
    end

    result['children'] = children unless children.empty?
    result
  else
    # Return primitive values as-is
    node
  end
end

def find_security_patterns(ast)
  # Extract security-relevant patterns from Ruby AST (Prism)
  patterns = []

  def traverse_node(node, patterns)
    return unless node && node.respond_to?(:type)

    case node.type
    when :call_node
      # Method calls - check for dangerous methods
      method_name = node.respond_to?(:name) ? node.name : nil
      
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
        
        loc = node.location if node.respond_to?(:location)
        line = loc ? loc.start_line : 0
        column = loc ? loc.start_column : 0

        if dangerous_methods.include?(method_str)
          patterns << {
            'type' => 'dangerous_method',
            'method' => method_str,
            'line' => line,
            'column' => column
          }
        end

        # SQL injection patterns
        if method_str.match?(/^(find|where|execute|query)$/)
          patterns << {
            'type' => 'potential_sql_injection',
            'method' => method_str,
            'line' => line,
            'column' => column
          }
        end

        # HTML output methods
        if method_str.match?(/^(html_safe|raw)$/)
          patterns << {
            'type' => 'html_output',
            'method' => method_str,
            'line' => line,
            'column' => column
          }
        end
      end

    when :interpolated_string_node, :interpolated_x_string_node
      # String interpolation and command execution
      loc = node.location if node.respond_to?(:location)
      patterns << {
        'type' => node.type == :interpolated_string_node ? 'string_interpolation' : 'command_execution',
        'line' => loc ? loc.start_line : 0,
        'column' => loc ? loc.start_column : 0
      }

    when :constant_read_node
      # Constant access - check for dangerous constants
      const_name = node.respond_to?(:name) ? node.name : nil
      if const_name && const_name.to_s.match?(/^(Kernel|Object|BasicObject)$/)
        loc = node.location if node.respond_to?(:location)
        patterns << {
          'type' => 'dangerous_constant',
          'constant' => const_name.to_s,
          'line' => loc ? loc.start_line : 0,
          'column' => loc ? loc.start_column : 0
        }
      end
    end

    # Recursively traverse children
    if node.respond_to?(:child_nodes)
      node.child_nodes.compact.each do |child|
        traverse_node(child, patterns)
      end
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

          # First, check for syntax errors using Prism directly
          prism_result = Prism.parse(code, filepath: filename)
          if !prism_result.success? && !prism_result.errors.empty?
            # Syntax errors detected - return error response
            first_error = prism_result.errors.first
            raise_error = {
              'id' => request_id,
              'status' => 'error',
              'success' => false,
              'error' => {
                'type' => 'SyntaxError',
                'message' => first_error.message,
                'line' => first_error.location.start_line,
                'column' => first_error.location.start_column
              }
            }
            puts JSON.generate(raise_error)
            STDOUT.flush
            next
          end

          # Parse the Ruby code using Prism AST
          ast = prism_result.value
          
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
            if node && node.respond_to?(:child_nodes)
              node_count += 1
              node.child_nodes.compact.each { |child| count_nodes.call(child) }
            elsif node.is_a?(Array)
              node.compact.each { |item| count_nodes.call(item) }
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

          # First, check for syntax errors using Prism directly
          prism_result = Prism.parse(code, filepath: filename)
          if !prism_result.success? && !prism_result.errors.empty?
            # Syntax errors detected - return error response
            first_error = prism_result.errors.first
            raise_error = {
              'id' => request_id,
              'status' => 'error',
              'success' => false,
              'error' => {
                'type' => 'SyntaxError',
                'message' => first_error.message,
                'line' => first_error.location.start_line,
                'column' => first_error.location.start_column
              }
            }
            puts JSON.generate(raise_error)
            STDOUT.flush
            next
          end

          # Parse the Ruby code using Prism AST
          ast = prism_result.value
          
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
            if node && node.respond_to?(:child_nodes)
              node_count += 1
              node.child_nodes.compact.each { |child| count_nodes.call(child) }
            elsif node.is_a?(Array)
              node.compact.each { |item| count_nodes.call(item) }
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