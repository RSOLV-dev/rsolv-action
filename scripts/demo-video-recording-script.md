# RSOLV Demo Video Recording Script & Setup

## Pre-Recording Setup Checklist

### 1. Environment Setup (30 minutes before recording)
```bash
# Terminal 1: Ensure RSOLV-action is ready
cd /Users/dylan/dev/rsolv/RSOLV-action
bun install
bun test # Ensure tests pass
export GITHUB_TOKEN=your_github_token

# Terminal 2: Create demo repository
mkdir -p ~/demo/rsolv-sql-injection-demo
cd ~/demo/rsolv-sql-injection-demo
git init
```

### 2. Create Demo Files
Create the vulnerable code file:
```bash
mkdir -p src/auth
cat > src/auth/login.js << 'EOF'
const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'ecommerce'
});

// VULNERABLE: Direct string concatenation allows SQL injection
function authenticateUser(username, password) {
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results.length > 0 ? results[0] : null);
    });
  });
}

// Additional vulnerable endpoint
function getUserOrders(userId) {
  // VULNERABLE: No input validation
  const query = `SELECT * FROM orders WHERE user_id = ${userId}`;
  
  return new Promise((resolve, reject) => {
    connection.query(query, (error, results) => {
      if (error) reject(error);
      resolve(results);
    });
  });
}

module.exports = { authenticateUser, getUserOrders };
EOF

# Commit the vulnerable code
git add .
git commit -m "Initial authentication system"
```

### 3. Create GitHub Repository
1. Go to GitHub and create new repo: `demo-ecommerce-security`
2. Push the code:
```bash
git remote add origin https://github.com/YOUR_USERNAME/demo-ecommerce-security.git
git push -u origin main
```

### 4. Create the Issue
Create issue on GitHub with this content:
```markdown
Title: Critical: Security audit needed for authentication system

Our security team has flagged potential vulnerabilities in our authentication system. 
We need to review and fix any SQL injection vulnerabilities in the login flow.

This is critical as we process over $10M in daily transactions and any breach 
could result in significant financial and reputational damage.

Priority: CRITICAL
Labels: security, high-priority, bug
```

### 5. Browser Setup
- Open tabs:
  1. GitHub repo main page
  2. GitHub issue page
  3. RSOLV landing page (https://rsolv.dev)
  4. Terminal ready with demo commands

### 6. Recording Software Setup
- Use OBS Studio or QuickTime
- Resolution: 1920x1080
- Clean desktop background
- Hide personal bookmarks/info
- Increase terminal font size to 16pt

## Video Script (5-7 minutes)

### Scene 1: The Problem (30 seconds)
**[Show GitHub issue]**

"Hi, I'm Dylan from RSOLV. Let me show you how we turn critical security vulnerabilities 
into fixed pull requests in under 5 minutes.

Here's a real scenario: An e-commerce platform processing $10 million daily just discovered 
potential SQL injection vulnerabilities. Their security team flagged it as critical.

Manually, this would take a senior engineer 4 hours to analyze, fix, test, and document."

### Scene 2: Starting RSOLV (30 seconds)
**[Switch to terminal]**

"With RSOLV, we start by running our demo environment..."

```bash
cd /Users/dylan/dev/rsolv/RSOLV-action
bun run demo-env
```

"RSOLV is now ready to analyze and fix security issues automatically."

### Scene 3: Processing the Issue (60 seconds)
**[In demo environment]**

"First, I'll select 'Get Issue' and paste our GitHub issue URL..."

**[Show the analysis]**

"RSOLV immediately identifies this as a security-critical issue. Notice it estimates 
240 minutes for manual fixing versus just 5 minutes with RSOLV.

Now let's analyze the codebase..."

**[Select 'Analyze Issue']**

"RSOLV is scanning the repository for security vulnerabilities..."

### Scene 4: Security Detection (90 seconds)
**[Show security analysis results]**

"Here's where RSOLV shines. It found 2 SQL injection vulnerabilities:
1. In the authentication function - attackers could bypass login
2. In the getUserOrders function - attackers could extract the entire database

RSOLV calculates the business impact:
- Financial: $4.45 million potential loss
- Compliance: PCI-DSS and GDPR violations
- Reputation: 31% customer loss risk

This isn't just scanning - RSOLV understands the real-world impact."

### Scene 5: The Fix (90 seconds)
**[Show generated solution]**

"Now RSOLV generates a complete fix using parameterized queries - the industry 
standard for preventing SQL injection.

Look at this - it's not just replacing code. RSOLV:
- Maintains exact functionality
- Adds input validation
- Follows security best practices
- Includes comprehensive documentation"

**[Scroll through the PR description]**

"Every fix includes three levels of explanation:
1. Executive summary for stakeholders
2. Technical details for developers  
3. Educational content to prevent future vulnerabilities"

### Scene 6: Creating the PR (60 seconds)
**[Select 'Create Pull Request']**

"Let's create the pull request..."

**[Show the GitHub PR]**

"Here's our complete pull request with:
- Security fixes for both vulnerabilities
- Detailed explanations at three levels
- Compliance documentation
- ROI calculations showing $4.45M saved

All generated automatically in under 5 minutes."

### Scene 7: The ROI (45 seconds)
**[Show ROI calculation]**

"Let's talk ROI. This fix cost $15 with RSOLV. It prevented a $4.45 million breach.
That's a 296,666% return on investment.

But it's not just about one fix. RSOLV continuously monitors and fixes vulnerabilities 
across your entire codebase, turning your backlog from a liability into an asset."

### Scene 8: Call to Action (30 seconds)
**[Show RSOLV landing page]**

"RSOLV works with your existing GitHub workflow. We support 80+ security patterns 
across JavaScript, TypeScript, Python, Ruby, and Java.

Want to see what vulnerabilities exist in your codebase right now? 

Visit rsolv.dev to get early access. We'll analyze your repositories and show you 
exactly how much risk you're carrying - and how quickly we can fix it.

Don't wait for a breach. Fix vulnerabilities today with RSOLV."

## Post-Recording Checklist

1. **Edit the video:**
   - Add intro/outro with RSOLV logo
   - Add captions for key points
   - Blur any sensitive information
   - Add background music (subtle)

2. **Create thumbnail:**
   - "$4.45M Saved in 5 Minutes"
   - Show before/after code
   - RSOLV logo

3. **Upload locations:**
   - YouTube (unlisted for prospects)
   - Vimeo (backup)
   - Landing page embed
   - Include in outreach emails

4. **Prepare companion materials:**
   - PDF of the PR description
   - One-page ROI calculator
   - Demo repository link

## Key Messages to Emphasize

1. **Speed**: 4 hours → 5 minutes
2. **Accuracy**: Finds ALL vulnerabilities
3. **ROI**: $15 fix prevents $4.45M breach  
4. **Education**: Learn while fixing
5. **Integration**: Works with existing workflow

## Common Mistakes to Avoid

- Don't go too fast through the security analysis
- Don't skip the business impact section
- Don't forget to show the three-tier explanations
- Don't make it too technical - executives watch too
- Don't forget the call to action

## Alternative Shorter Version (2 minutes)

For social media, create a 2-minute version focusing on:
1. The problem (15 sec)
2. Running RSOLV (15 sec)
3. Finding vulnerabilities (30 sec)
4. The fix and ROI (45 sec)
5. Call to action (15 sec)