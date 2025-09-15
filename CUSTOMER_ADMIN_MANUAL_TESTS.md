# Customer Admin Dashboard Manual Test Checklist

## Staging Environment Test Guide
**URL**: https://api.rsolv-staging.com
**Date**: 2025-09-14
**Features**: RFC-056 Increments 4-7
**Tag**: v1.1.0-customer-management

## Prerequisites
- Admin credentials: `admin@rsolv.dev` / `AdminP@ssw0rd2025!`
- Modern browser with DevTools
- Network connectivity to staging environment

## Test Checklist

### 1. Admin Login ✅
- [ ] Navigate to https://api.rsolv-staging.com/admin/login
- [ ] Verify login form displays with email and password fields
- [ ] Enter admin credentials
- [ ] Submit form
- [ ] Verify redirect to admin dashboard at `/admin/auth`
- [ ] Verify "View Customers" link is visible

### 2. Customer List View (Increment 4-5)
- [ ] Click "View Customers →" from dashboard
- [ ] Verify URL changes to `/admin/customers`
- [ ] **Check UI Elements:**
  - [ ] "New Customer" button (blue, top right)
  - [ ] Status filter dropdown (All/Active/Inactive)
  - [ ] Customer table with columns:
    - [ ] Name
    - [ ] Email
    - [ ] Status
    - [ ] Plan
    - [ ] Usage
    - [ ] Created
    - [ ] Actions
  - [ ] Pagination info (e.g., "Showing 1 to 20 of X")

### 3. Customer Actions Column (Increment 6)
- [ ] Verify each customer row has three action buttons:
  - [ ] **View** (green) - links to detail page
  - [ ] **Edit** (blue) - opens edit modal
  - [ ] **Delete** (red) - opens confirmation dialog

### 4. Create New Customer
- [ ] Click "New Customer" button
- [ ] Verify modal opens with form fields:
  - [ ] Name (required)
  - [ ] Email (required)
  - [ ] Password (required)
  - [ ] Plan dropdown (trial/pro/pay_as_you_go/enterprise)
  - [ ] Monthly Limit (number)
  - [ ] Active checkbox
- [ ] Fill in test data:
  ```
  Name: Test Customer
  Email: test@example.com
  Password: TestPass123!
  Plan: Pro
  Monthly Limit: 1000
  Active: ✓
  ```
- [ ] Click Save
- [ ] Verify success message appears
- [ ] Verify new customer appears in list

### 5. Edit Customer
- [ ] Click "Edit" button on any customer
- [ ] Verify modal opens with pre-filled data
- [ ] Modify at least one field
- [ ] Click Save
- [ ] Verify success message
- [ ] Verify changes reflected in list

### 6. Delete Customer
- [ ] Click "Delete" button on test customer
- [ ] Verify confirmation dialog shows:
  - [ ] "Delete Customer" title
  - [ ] Customer name in message
  - [ ] "This action cannot be undone" warning
- [ ] Click Delete button
- [ ] Verify success message
- [ ] Verify customer removed from list

### 7. Customer Detail View (Increment 7)
- [ ] Click "View" button on any customer
- [ ] Verify URL changes to `/admin/customers/:id`
- [ ] **Check page sections:**
  - [ ] Customer Information (name, email, plan, status)
  - [ ] Usage Statistics with progress bar
  - [ ] API Keys section
  - [ ] "Back to Customers" link
- [ ] Verify breadcrumb navigation:
  - [ ] Admin → Customers → [Customer Name]

### 8. API Key Generation
- [ ] On customer detail page, locate "API Keys" section
- [ ] Click "Generate New Key" button
- [ ] Verify success message
- [ ] Verify new key appears in list with:
  - [ ] Name ("API Key")
  - [ ] Masked key (rsolv_****)
  - [ ] Creation date

### 9. Sorting & Filtering
- [ ] **Test Sorting:**
  - [ ] Click "Name" header - verify sort indicator
  - [ ] Click "Email" header - verify sort changes
  - [ ] Click "Created" header - verify sort by date
- [ ] **Test Filtering:**
  - [ ] Select "Active" from status filter
  - [ ] Verify only active customers shown
  - [ ] Select "Inactive"
  - [ ] Verify only inactive customers shown
  - [ ] Select "All" to reset

### 10. Responsive Design
- [ ] Test on desktop (>1024px)
- [ ] Test on tablet (768px)
- [ ] Test on mobile (<640px)
- [ ] Verify all features accessible on each size

### 11. Dark Mode
- [ ] Toggle dark mode (if available)
- [ ] Verify all UI elements have proper dark styling
- [ ] Check modals maintain dark theme
- [ ] Verify text remains readable

### 12. Error Handling
- [ ] Try creating customer with duplicate email
- [ ] Try submitting forms with empty required fields
- [ ] Verify appropriate error messages display

## Performance Checks
- [ ] Page load time < 2 seconds
- [ ] Modal open/close smooth
- [ ] No console errors in DevTools
- [ ] Network requests complete successfully

## Security Verification
- [ ] Verify HTTPS on all pages
- [ ] Check session timeout after inactivity
- [ ] Verify non-admin users cannot access `/admin/*` routes
- [ ] API keys are masked in UI

## Test Results Summary
- **Tested By**: _________________
- **Date**: _________________
- **Browser/Version**: _________________
- **Issues Found**: _________________
- **Overall Status**: [ ] PASS [ ] FAIL

## Notes
- LiveView features require WebSocket connection
- Some actions update in real-time without page refresh
- All changes persist across sessions
- API keys cannot be retrieved after generation (security feature)