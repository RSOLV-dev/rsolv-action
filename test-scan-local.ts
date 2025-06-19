#!/usr/bin/env bun
/**
 * Local test script for demonstrating RSOLV security scanning
 * This simulates what the GitHub Action would do in scan mode
 */

import { ScanOrchestrator } from './src/scanner/index.js';
import { SecurityDetectorV2 } from './src/security/detector-v2.js';
import { createPatternSource } from './src/security/pattern-source.js';
import { logger } from './src/utils/logger.js';

// Configure logger for demo
logger.info('🔍 RSOLV Security Scanner - Local Demo');
logger.info('=====================================');

// Sample vulnerable code snippets to demonstrate detection
const vulnerableCode = {
  javascript: {
    path: 'demo/vulnerable.js',
    content: `
// SQL Injection vulnerability
app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// XSS vulnerability
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send('<h1>Results for: ' + searchTerm + '</h1>');
});

// Command Injection
const exec = require('child_process').exec;
app.post('/ping', (req, res) => {
  exec('ping ' + req.body.host, (err, stdout) => {
    res.send(stdout);
  });
});

// Hardcoded secret
const API_KEY = "sk-1234567890abcdef";
const DATABASE_PASSWORD = "admin123";
`
  },
  python: {
    path: 'demo/vulnerable.py',
    content: `
import os
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)

# SQL Injection
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = conn.execute(query)
    return str(result.fetchall())

# Command Injection
@app.route('/run')
def run_command():
    cmd = request.args.get('cmd')
    result = os.system(cmd)
    return f"Command executed: {result}"

# XSS via template injection
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    template = '<h1>Hello ' + name + '</h1>'
    return render_template_string(template)

# Weak cryptography
import md5
def hash_password(password):
    return md5.new(password).hexdigest()
`
  },
  ruby: {
    path: 'demo/vulnerable.rb',
    content: `
class UsersController < ApplicationController
  # SQL Injection
  def search
    name = params[:name]
    @users = User.where("name LIKE '%#{name}%'")
    render json: @users
  end

  # Command Injection
  def backup
    file = params[:file]
    system("tar -czf backup.tar.gz #{file}")
    render plain: "Backup created"
  end

  # Path Traversal
  def download
    filename = params[:file]
    send_file "/uploads/#{filename}"
  end

  # Mass Assignment
  def update
    @user = User.find(params[:id])
    @user.update(params[:user])  # Allows setting admin flag
    redirect_to @user
  end
end
`
  }
};

async function runDemo() {
  try {
    // Create detector
    const detector = new SecurityDetectorV2(createPatternSource());
    
    // Test each language
    for (const [language, file] of Object.entries(vulnerableCode)) {
      logger.info(`\n📂 Scanning ${file.path} (${language})`);
      logger.info('─'.repeat(50));
      
      const vulnerabilities = await detector.detect(file.content, language);
      
      if (vulnerabilities.length === 0) {
        logger.info('✅ No vulnerabilities found');
      } else {
        logger.warn(`⚠️  Found ${vulnerabilities.length} vulnerabilities:`);
        
        // Group by type
        const grouped = vulnerabilities.reduce((acc, vuln) => {
          if (!acc[vuln.type]) {
            acc[vuln.type] = [];
          }
          acc[vuln.type].push(vuln);
          return acc;
        }, {} as Record<string, typeof vulnerabilities>);
        
        for (const [type, vulns] of Object.entries(grouped)) {
          logger.info(`\n  🔴 ${type.replace(/-/g, ' ').toUpperCase()} (${vulns.length} instances)`);
          for (const vuln of vulns.slice(0, 2)) { // Show max 2 examples
            logger.info(`     Line ${vuln.line}: ${vuln.description}`);
            if (vuln.snippet) {
              logger.info(`     Code: ${vuln.snippet.trim()}`);
            }
          }
          if (vulns.length > 2) {
            logger.info(`     ... and ${vulns.length - 2} more`);
          }
        }
      }
    }
    
    logger.info('\n\n📊 SCAN SUMMARY');
    logger.info('═'.repeat(50));
    logger.info('This demo shows how RSOLV can proactively scan code for vulnerabilities.');
    logger.info('In a real GitHub Action workflow:');
    logger.info('  1. The entire repository would be scanned');
    logger.info('  2. Vulnerabilities would be grouped by type');
    logger.info('  3. GitHub issues would be created automatically');
    logger.info('  4. RSOLV can then process those issues to generate fixes');
    logger.info('\nWith NodeGoat or other vulnerable apps, we\'d find many more real vulnerabilities!');
    
  } catch (error) {
    logger.error('Demo failed:', error);
    process.exit(1);
  }
}

// Run the demo
runDemo();