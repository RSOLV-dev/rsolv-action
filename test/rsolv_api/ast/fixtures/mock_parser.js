#!/usr/bin/env node
/**
 * Mock JavaScript parser for testing Port supervision.
 */

const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

rl.on('line', (line) => {
  try {
    const request = JSON.parse(line);
    
    let response;
    if (request.command === 'HEALTH_CHECK') {
      response = { status: 'healthy', id: request.id };
    } else if (request.command === 'parse') {
      // Simulate AST parsing
      response = {
        id: request.id,
        result: {
          ast: { type: 'Program', body: [] },
          language: 'javascript',
          parser_version: '1.0.0'
        }
      };
    } else {
      response = {
        id: request.id,
        result: { echo: request.command || 'unknown' }
      };
    }
    
    console.log(JSON.stringify(response));
  } catch (e) {
    const errorResponse = {
      id: request ? request.id : null,
      error: e.message
    };
    console.log(JSON.stringify(errorResponse));
  }
});