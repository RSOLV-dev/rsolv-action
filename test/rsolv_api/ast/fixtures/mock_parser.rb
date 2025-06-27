#!/usr/bin/env ruby
# Mock Ruby parser for testing Port supervision.

require 'json'

STDOUT.sync = true
STDIN.sync = true

while line = STDIN.gets
  begin
    request = JSON.parse(line.strip)
    
    response = case request['command']
    when 'HEALTH_CHECK'
      { 'status' => 'healthy', 'id' => request['id'] }
    when 'parse'
      # Simulate AST parsing
      {
        'id' => request['id'],
        'result' => {
          'ast' => { 'type' => 'Program', 'body' => [] },
          'language' => 'ruby',
          'parser_version' => '1.0.0'
        }
      }
    else
      {
        'id' => request['id'],
        'result' => { 'echo' => request['command'] || 'unknown' }
      }
    end
    
    puts JSON.generate(response)
  rescue => e
    error_response = {
      'id' => request ? request['id'] : nil,
      'error' => e.message
    }
    puts JSON.generate(error_response)
  end
end