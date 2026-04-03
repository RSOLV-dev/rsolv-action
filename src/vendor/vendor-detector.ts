/**
 * RFC-047: Vendor Library Detection Implementation
 */

import { Library } from './types.js';
import * as path from 'path';
import * as fs from 'fs/promises';

export class VendorDetector {
  private readonly VENDOR_PATTERNS = [
    'node_modules',
    'vendor',
    'bower_components',
    'jspm_packages',
    'packages',
    'third_party',
    'external',
    'libs',
    'dependencies',
    'dist',
    // Rails asset pipeline
    'app/assets/javascripts',
    'public/assets',
    'public/packs',
    // Django
    'static/vendor',
    // Laravel
    'public/vendor',
    // General build outputs
    'build',
    '_build',
    'out'
  ];
  
  private readonly MINIFIED_PATTERNS = [
    '.min.js',
    '-min.js',
    '.bundle.js',
    '.min.css',
    '-min.css'
  ];
  
  /**
   * Directories that commonly hold static assets (vendor code when combined with size heuristic).
   * Files > LARGE_FILE_THRESHOLD in these dirs are likely third-party libraries.
   */
  private readonly STATIC_ASSET_DIRS = [
    '/static/',
    '/assets/',
    '/public/',
    '/wwwroot/',
    '/resources/',
  ];

  /**
   * Files larger than this (in bytes) in static asset directories are likely vendor libraries.
   */
  private readonly LARGE_FILE_THRESHOLD = 50_000;

  private readonly VENDOR_INDICATORS = {
    filePatterns: [
      /jquery[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /bootstrap[.-]?([\d.]+)?(?:\.min)?\.(?:js|css)$/i,
      /angular[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /react[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /vue[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /lodash[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /moment[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /d3[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /chart[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /raphael[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /backbone[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /underscore[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /ember[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /handlebars[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /axios[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /three[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /popper[.-]?([\d.]+)?(?:\.min)?\.js$/i,
      /leaflet[.-]?([\d.]+)?(?:\.min)?\.js$/i,
    ],
    headerComments: [
      /\/\*!?\s*jQuery\s+v?([\d.]+)/i,
      /\/\*!?\s*Bootstrap\s+v?([\d.]+)/i,
      /\/\*!?\s*Angular\s+v?([\d.]+)/i,
      /\/\*!?\s*React\s+v?([\d.]+)/i,
      /\/\*!?\s*Vue\.js\s+v?([\d.]+)/i,
      /Copyright\s+\(c\)\s+.*\s+Foundation/i,
      /Licensed\s+under\s+MIT/i,
      /Licensed\s+under\s+the\s+Apache\s+License/i,
      /Copyright\s+\d{4}\s+Google/i,
      /Copyright\s+The\s+Closure\s+Library/i,
      /google\.charts|google\.load|goog\.provide/i,
      /\/\*!?\s*\w+\.js\s+v?\d+\.\d+\.\d+/
    ]
  };

  async isVendorFile(filePath: string, content?: string): Promise<boolean> {
    // Check if path contains vendor directory
    if (this.matchesVendorPattern(filePath)) {
      return true;
    }

    // Check if file is minified by filename
    if (this.isMinified(filePath)) {
      return true;
    }

    // Check if filename matches known vendor libraries
    if (this.matchesKnownLibrary(filePath)) {
      return true;
    }

    // Check if content is minified (long lines = bundled/minified vendor code)
    if (content && this.isContentMinified(content)) {
      return true;
    }

    // Check file content headers (license headers, library banners)
    if (await this.containsVendorIndicators(filePath, content)) {
      return true;
    }

    // Large files in static asset directories are likely vendor libraries
    if (content && this.isLargeStaticAsset(filePath, content)) {
      return true;
    }

    return false;
  }
  
  async containsVendorIndicators(filePath: string, content?: string): Promise<boolean> {
    // If content provided, check header comments
    if (content) {
      return this.hasVendorHeader(content);
    }
    
    // Try to read file and check header
    try {
      const fileContent = await fs.readFile(filePath, 'utf-8');
      // Only check first 500 chars for performance
      const header = fileContent.substring(0, 500);
      return this.hasVendorHeader(header);
    } catch {
      return false;
    }
  }
  
  async identifyLibrary(filePath: string, content?: string): Promise<Library | null> {
    // First check if it's even a vendor file
    const isVendor = await this.isVendorFile(filePath) || 
                    (content && this.hasVendorHeader(content));
    
    if (!isVendor) {
      return null;
    }
    
    // Try to extract from content/header first if provided
    // (more accurate than path-based detection)
    if (content) {
      const headerInfo = this.extractFromHeader(content);
      if (headerInfo) {
        return headerInfo;
      }
    }
    
    // Fall back to path extraction
    const pathInfo = this.extractFromPath(filePath);
    if (pathInfo) {
      return pathInfo;
    }
    
    // Try to read file if no content provided
    if (!content) {
      try {
        const fileContent = await fs.readFile(filePath, 'utf-8');
        const header = fileContent.substring(0, 500);
        return this.extractFromHeader(header);
      } catch {
        // Fall through
      }
    }
    
    // Generic vendor file without specific library info
    return {
      name: 'unknown-vendor',
      version: 'unknown'
    };
  }
  
  private matchesVendorPattern(filePath: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');
    return this.VENDOR_PATTERNS.some(pattern => 
      normalizedPath.includes(`/${pattern}/`) || 
      normalizedPath.includes(`${pattern}/`)
    );
  }
  
  private isMinified(filePath: string): boolean {
    const filename = path.basename(filePath).toLowerCase();
    return this.MINIFIED_PATTERNS.some(pattern =>
      filename.includes(pattern)
    );
  }

  /**
   * Detect minified/bundled content by analyzing line lengths.
   * Minified files typically have very long lines (1000+ chars avg)
   * because whitespace and newlines are stripped during minification.
   */
  private isContentMinified(content: string): boolean {
    // Only check JS/CSS files by content analysis
    const lines = content.split('\n');
    if (lines.length === 0) return false;

    // Single-line files over 1KB are almost certainly minified
    if (lines.length <= 3 && content.length > 1000) {
      return true;
    }

    // Check average line length (excluding empty lines and short comment lines)
    const significantLines = lines.filter(l => l.length > 10);
    if (significantLines.length === 0) return false;

    const avgLineLength = significantLines.reduce((sum, l) => sum + l.length, 0) / significantLines.length;

    // Average line length > 500 chars strongly indicates minified code
    if (avgLineLength > 500) {
      return true;
    }

    // Any single line over 5000 chars is a strong minification signal
    if (lines.some(l => l.length > 5000)) {
      return true;
    }

    return false;
  }
  
  /**
   * Detect large files in static asset directories as likely vendor libraries.
   * A 107KB JS file in /static/ is almost certainly a third-party library,
   * not hand-written application code.
   */
  private isLargeStaticAsset(filePath: string, content: string): boolean {
    const normalizedPath = filePath.replace(/\\/g, '/');
    const isJsOrCss = /\.(js|css)$/.test(normalizedPath);
    if (!isJsOrCss) return false;

    const inStaticDir = this.STATIC_ASSET_DIRS.some(dir => normalizedPath.includes(dir));
    if (!inStaticDir) return false;

    return content.length > this.LARGE_FILE_THRESHOLD;
  }

  private matchesKnownLibrary(filePath: string): boolean {
    const filename = path.basename(filePath);
    return this.VENDOR_INDICATORS.filePatterns.some(pattern => 
      pattern.test(filename)
    );
  }
  
  private hasVendorHeader(content: string): boolean {
    return this.VENDOR_INDICATORS.headerComments.some(pattern => 
      pattern.test(content)
    );
  }
  
  private extractFromPath(filePath: string): Library | null {
    const filename = path.basename(filePath);
    
    // Try each known library pattern
    for (const pattern of this.VENDOR_INDICATORS.filePatterns) {
      const match = filename.match(pattern);
      if (match) {
        // Extract library name and version
        const libraryName = this.getLibraryNameFromPattern(pattern);
        const version = match[1] || 'unknown';
        
        return {
          name: libraryName,
          version: version
        };
      }
    }
    
    // Special case for files like jquery-3.6.0.min.js
    const versionMatch = filename.match(/^([\w-]+)[.-]([\d.]+)(?:\.min)?\.(?:js|css)$/);
    if (versionMatch) {
      return {
        name: versionMatch[1].toLowerCase(),
        version: versionMatch[2]
      };
    }
    
    return null;
  }
  
  private extractFromHeader(content: string): Library | null {
    // Special case for Bootstrap CSS with URL
    const bootstrapMatch = content.match(/\/\*!?\s*Bootstrap\s+v?([\d.]+)(?:\s+\([^)]+\))?/i);
    if (bootstrapMatch) {
      return {
        name: 'bootstrap',
        version: bootstrapMatch[1] || 'unknown'
      };
    }
    
    // Try each header pattern
    for (const pattern of this.VENDOR_INDICATORS.headerComments) {
      const match = content.match(pattern);
      if (match) {
        // Extract library name from the pattern
        const libraryName = this.getLibraryNameFromHeader(content, pattern);
        const version = match[1] || 'unknown';
        
        if (libraryName) {
          return {
            name: libraryName.toLowerCase(),
            version: version
          };
        }
      }
    }
    
    return null;
  }
  
  private getLibraryNameFromPattern(pattern: RegExp): string {
    const patternStr = pattern.source;
    // Extract library name from pattern (e.g., "jquery" from /jquery[.-]?[\d.]+/)
    const match = patternStr.match(/^(\w+)/);
    return match ? match[1].toLowerCase() : 'unknown';
  }
  
  private getLibraryNameFromHeader(content: string, pattern: RegExp): string | null {
    const patternStr = pattern.source;
    
    // Special cases for known libraries
    if (patternStr.includes('jQuery')) return 'jquery';
    if (patternStr.includes('Bootstrap')) return 'bootstrap';
    if (patternStr.includes('Angular')) return 'angular';
    if (patternStr.includes('React')) return 'react';
    if (patternStr.includes('Vue')) return 'vue';
    
    // Try to extract from content
    const nameMatch = content.match(/\/\*!?\s*(\w+)(?:\.js)?\s+v/i);
    if (nameMatch) {
      return nameMatch[1].toLowerCase();
    }
    
    return null;
  }
}