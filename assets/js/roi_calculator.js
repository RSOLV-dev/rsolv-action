/**
 * ROI Calculator Module
 * Provides functionality for the ROI calculator on the landing page
 */

/**
 * Initialize the ROI calculator
 */
export function initRoiCalculator() {
  // Get calculator elements
  const teamSizeSelect = document.getElementById('team-size');
  const avgSalarySelect = document.getElementById('avg-salary');
  const platformCountSelect = document.getElementById('platform-count');
  const monthlyIssuesSlider = document.getElementById('monthly-issues');
  const monthlyIssuesValue = document.getElementById('monthly-issues-value');
  
  // Get output elements
  const annualCostEl = document.getElementById('annual-cost');
  const contextSwitchingEl = document.getElementById('context-switching');
  const securityOverheadEl = document.getElementById('security-overhead');
  const crossPlatformEl = document.getElementById('cross-platform-coordination');
  const inefficiencyCostEl = document.getElementById('inefficiency-cost');
  
  const platformSavingsEl = document.getElementById('platform-savings');
  const securityEnhancementEl = document.getElementById('security-enhancement');
  const educationalBenefitEl = document.getElementById('educational-benefit');
  const rsolvCostEl = document.getElementById('rsolv-cost');
  const annualSavingsEl = document.getElementById('annual-savings');
  
  // Platform-specific and security elements
  const jiraSavingsEl = document.getElementById('jira-savings');
  const linearSavingsEl = document.getElementById('linear-savings');
  const githubSavingsEl = document.getElementById('github-savings');
  const gitlabSavingsEl = document.getElementById('gitlab-savings');
  const securityComplianceEl = document.getElementById('security-compliance-savings');
  const educationalSavingsEl = document.getElementById('educational-savings');
  
  // Visualization elements
  const savingsBarEl = document.getElementById('savings-bar');
  const costBarEl = document.getElementById('cost-bar');
  const percentCostEl = document.getElementById('percent-cost');
  const percentSavingsEl = document.getElementById('percent-savings');
  const pricingTierEl = document.getElementById('pricing-tier');
  const monthlyFixesEl = document.getElementById('monthly-fixes');
  
  // ROI elements
  const roiEl = document.getElementById('roi');
  const paybackEl = document.getElementById('payback');
  
  // Update monthly issues value display
  if (monthlyIssuesSlider && monthlyIssuesValue) {
    monthlyIssuesSlider.addEventListener('input', function() {
      monthlyIssuesValue.textContent = `${this.value} issues/month`;
      updateCalculator();
    });
  }
  
  // Add event listeners to form fields
  if (teamSizeSelect) {
    teamSizeSelect.addEventListener('change', updateCalculator);
  }
  
  if (avgSalarySelect) {
    avgSalarySelect.addEventListener('change', updateCalculator);
  }
  
  if (platformCountSelect) {
    platformCountSelect.addEventListener('change', updateCalculator);
  }
  
  // Main calculator update function
  function updateCalculator() {
    // Get form values
    const teamSize = parseInt(teamSizeSelect?.value || '10', 10);
    const avgSalary = parseInt(avgSalarySelect?.value || '150000', 10);
    const platformCount = parseInt(platformCountSelect?.value || '2', 10);
    const monthlyIssues = parseInt(monthlyIssuesSlider?.value || '50', 10);
    
    // Calculate ROI metrics
    const result = calculateRoi({
      teamSize,
      avgSalary,
      platformCount,
      monthlyIssues
    });
    
    // Update UI elements if they exist
    if (annualCostEl) annualCostEl.textContent = '$' + result.annualCost.toLocaleString();
    if (contextSwitchingEl) contextSwitchingEl.textContent = (result.contextSwitching * 100) + '%';
    if (securityOverheadEl) securityOverheadEl.textContent = (result.securityOverhead * 100) + '%';
    if (crossPlatformEl) crossPlatformEl.textContent = (result.crossPlatformCoordination * 100) + '%';
    if (inefficiencyCostEl) inefficiencyCostEl.textContent = '$' + result.inefficiencyCost.toLocaleString();
    
    if (platformSavingsEl) platformSavingsEl.textContent = (result.platformSavings * 100) + '%';
    if (securityEnhancementEl) securityEnhancementEl.textContent = (result.securityEnhancement * 100) + '%';
    if (educationalBenefitEl) educationalBenefitEl.textContent = (result.educationalBenefit * 100) + '%';
    if (rsolvCostEl) rsolvCostEl.textContent = '$' + result.rsolvCost.toLocaleString();
    if (annualSavingsEl) annualSavingsEl.textContent = '$' + result.annualSavings.toLocaleString();
    
    // Update platform-specific and security savings
    if (jiraSavingsEl) jiraSavingsEl.textContent = '$' + result.jiraSavings.toLocaleString();
    if (linearSavingsEl) linearSavingsEl.textContent = '$' + result.linearSavings.toLocaleString();
    if (githubSavingsEl) githubSavingsEl.textContent = '$' + result.githubSavings.toLocaleString();
    if (gitlabSavingsEl) gitlabSavingsEl.textContent = '$' + result.gitlabSavings.toLocaleString();
    if (securityComplianceEl) securityComplianceEl.textContent = '$' + result.securityComplianceSavings.toLocaleString();
    if (educationalSavingsEl) educationalSavingsEl.textContent = '$' + result.educationalSavings.toLocaleString();
    
    // Update visualization
    if (savingsBarEl) savingsBarEl.style.width = `${Math.max(result.savingsPercentage, 1)}%`;
    if (costBarEl) costBarEl.style.width = `${Math.max(result.costPercentage, 1)}%`;
    if (percentCostEl) percentCostEl.textContent = `${Math.round(result.costPercentage)}%`;
    if (percentSavingsEl) percentSavingsEl.textContent = `${Math.round(result.savingsPercentage)}%`;
    
    // Update pricing tier and monthly fixes
    if (monthlyFixesEl) monthlyFixesEl.textContent = result.monthlyFixes.toString();
    if (pricingTierEl) pricingTierEl.textContent = `${result.tierName} ($${result.pricePerFix}/fix)`;
    
    // Update ROI and payback period
    if (roiEl) roiEl.textContent = result.roi + '%';
    if (paybackEl) paybackEl.textContent = `~${result.paybackMonths.toFixed(1)} months`;
  }
  
  // Initialize calculator with default values
  updateCalculator();
}

/**
 * Calculate ROI metrics based on input values
 * 
 * @param {Object} params - Parameters for the calculation
 * @param {number} params.teamSize - Number of engineers
 * @param {number} params.avgSalary - Average annual salary
 * @param {number} params.platformCount - Number of platforms/ticket systems
 * @param {number} params.monthlyIssues - Monthly issues to be processed
 * @returns {Object} Calculated metrics
 */
export function calculateRoi(params) {
  const { teamSize, avgSalary, platformCount, monthlyIssues } = params;
  
  // Calculate base metrics
  const annualCost = teamSize * avgSalary;
  
  // Calculate inefficiency metrics based on platform count and security needs
  const contextSwitching = 0.05 + (platformCount * 0.05); // 5% base + 5% per platform
  const securityOverhead = 0.1 + (platformCount * 0.03); // 10% base + 3% per platform (increased to reflect higher security importance)
  const crossPlatformCoordination = 0.08 * (platformCount > 1 ? platformCount / 2 : 0); // New metric: cross-platform coordination overhead
  const inefficiencyCost = annualCost * (contextSwitching + securityOverhead + crossPlatformCoordination);
  
  // Calculate RSOLV benefits with increased focus on security and cross-platform
  const platformSavings = Math.min(0.08 + (platformCount * 0.045), 0.25); // Cap at 25% (increased from 20%)
  const securityEnhancement = Math.min(0.12 + (platformCount * 0.025), 0.25); // Cap at 25% (increased from 15%)
  const educationalBenefit = 0.05; // New benefit: educational component reduces recurring issues
  
  // Calculate RSOLV pricing 
  const rsolvFixRate = 0.8; // 80% success rate
  const monthlyFixes = Math.round(monthlyIssues * rsolvFixRate);
  
  // Apply volume-based pricing tiers (updated to match new pricing structure)
  let pricePerFix = 15;
  let tierName = 'Security-First';
  
  if (monthlyFixes > 500 || platformCount >= 4) {
    pricePerFix = 12;
    tierName = 'Enterprise';
  } else if (monthlyFixes > 250 || platformCount === 3) {
    pricePerFix = 13;
    tierName = 'Multi-Platform';
  } else if (monthlyFixes > 100 || platformCount === 2) {
    pricePerFix = 14;
    tierName = 'Cross-Platform';
  }
  
  const rsolvCost = monthlyFixes * pricePerFix * 12;
  
  // Calculate savings and ROI with educational component
  const annualSavings = (annualCost * (platformSavings + securityEnhancement + educationalBenefit)) - rsolvCost;
  const roi = rsolvCost > 0 ? Math.round((annualSavings / rsolvCost) * 100) : 0;
  const paybackMonths = rsolvCost > 0 ? (rsolvCost / (annualSavings / 12)) : 0;
  
  // Calculate percentages for visualization
  const costPercentage = rsolvCost > 0 ? Math.round((rsolvCost / (annualSavings + rsolvCost)) * 100) : 0;
  const savingsPercentage = 100 - costPercentage;
  
  // Calculate platform-specific and security savings
  // Updated distribution percentages based on platform impact with security focus
  const jiraPercent = 0.15;
  const linearPercent = 0.18;
  const githubPercent = 0.25; // Reduced from 0.35
  const gitlabPercent = 0.22; // Reduced from 0.32
  const securityCompliancePercent = 0.15; // New category
  const educationalPercent = 0.05; // New category
  
  const totalBenefit = annualCost * (platformSavings + securityEnhancement + educationalBenefit);
  const jiraSavings = Math.round(totalBenefit * jiraPercent);
  const linearSavings = Math.round(totalBenefit * linearPercent);
  const githubSavings = Math.round(totalBenefit * githubPercent);
  const gitlabSavings = Math.round(totalBenefit * gitlabPercent);
  const securityComplianceSavings = Math.round(totalBenefit * securityCompliancePercent);
  const educationalSavings = Math.round(totalBenefit * educationalPercent);
  
  return {
    annualCost,
    contextSwitching,
    securityOverhead,
    crossPlatformCoordination,
    inefficiencyCost,
    platformSavings,
    securityEnhancement,
    educationalBenefit,
    rsolvCost,
    annualSavings,
    monthlyFixes,
    pricePerFix,
    tierName,
    roi,
    paybackMonths,
    jiraSavings,
    linearSavings,
    githubSavings,
    gitlabSavings,
    securityComplianceSavings,
    educationalSavings,
    costPercentage,
    savingsPercentage
  };
}