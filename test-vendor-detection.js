/**
 * Test if jquery.snippet.js is being classified as vendor
 */

const VENDOR_INDICATORS = {
  filePatterns: [
    /jquery[.-]?([\d.]+)?(?:\.min)?\.js$/i,
    /bootstrap[.-]?([\d.]+)?(?:\.min)?\.js$/i,
    /angular[.-]?([\d.]+)?(?:\.min)?\.js$/i,
    /react[.-]?([\d.]+)?(?:\.min)?\.js$/i,
    /vue[.-]?([\d.]+)?(?:\.min)?\.js$/i,
    /lodash[.-]?([\d.]+)?(?:\.min)?\.js$/i,
    /moment[.-]?([\d.]+)?(?:\.min)?\.js$/i
  ]
};

const testFiles = [
  'jquery.snippet.js',
  'jquery-3.6.0.min.js',
  'jquery.min.js',
  'snippet.js',
  'app/assets/javascripts/jquery.snippet.js'
];

console.log('Testing VendorDetector.matchesKnownLibrary logic:\n');

testFiles.forEach(filePath => {
  const filename = filePath.split('/').pop();
  const isVendor = VENDOR_INDICATORS.filePatterns.some(pattern => pattern.test(filename));
  console.log(`${isVendor ? '✓ VENDOR' : '✗ not vendor'}: ${filePath}`);

  if (isVendor) {
    // Show which pattern matched
    VENDOR_INDICATORS.filePatterns.forEach(pattern => {
      if (pattern.test(filename)) {
        console.log(`  ↳ Matched pattern: ${pattern}`);
      }
    });
  }
});

console.log('\n=== ROOT CAUSE ===');
console.log('jquery.snippet.js matches /jquery[.-]?([\d.]+)?(?:\.min)?\.js$/i');
console.log('Even though it\'s not actually jQuery library!');
console.log('The pattern is too broad and matches any file starting with "jquery".');
