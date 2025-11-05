# Support Template Refactoring - Before/After Examples

Using existing `Docs.Callout` component from our Tailwind UI Plus library.

## Setup (One-Time Change)

**File**: `lib/rsolv_web/controllers/support_html.ex`

```elixir
defmodule RsolvWeb.SupportHTML do
  use RsolvWeb, :html
  use RsolvWeb.Components.Docs  # ← Add this line

  embed_templates "support_html/*"
end
```

This imports: `callout`, `breadcrumbs`, `code_block`, `docs_layout`, `sidebar_nav`, `table_of_contents`

## Example 1: Alert Box Refactoring

### BEFORE (13 lines):
```heex
<div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
  <div class="flex items-start">
    <svg class="w-5 h-5 text-yellow-600 dark:text-yellow-400 mr-3 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
    </svg>
    <div>
      <p class="font-semibold text-yellow-900 dark:text-yellow-200 mb-1">Security Note</p>
      <p class="text-sm text-yellow-800 dark:text-yellow-300">
        Store your API key securely using GitHub Secrets. Never commit it to your repository.
      </p>
    </div>
  </div>
</div>
```

### AFTER (3 lines):
```heex
<.callout variant="warning" title="Security Note">
  Store your API key securely using GitHub Secrets. Never commit it to your repository.
</.callout>
```

**Savings**: 77% reduction (13 → 3 lines)

---

## Example 2: Info Callout

### BEFORE (11 lines):
```heex
<div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
  <div class="flex items-start">
    <svg class="w-5 h-5 text-blue-600 dark:text-blue-400 mr-3 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
    </svg>
    <div class="text-sm text-blue-800 dark:text-blue-300">
      <p>For advanced configuration options, see the <a href="/docs/workflows" class="font-semibold hover:underline">Workflows documentation</a>.</p>
    </div>
  </div>
</div>
```

### AFTER (3 lines):
```heex
<.callout variant="info">
  For advanced configuration options, see the <a href="/docs/workflows" class="font-semibold hover:underline">Workflows documentation</a>.
</.callout>
```

**Savings**: 73% reduction (11 → 3 lines)

---

## Example 3: Success Message

### BEFORE (11 lines):
```heex
<div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
  <div class="flex items-start">
    <svg class="w-5 h-5 text-green-600 dark:text-green-400 mr-3 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
    </svg>
    <div class="text-sm text-green-800 dark:text-green-300">
      <p><strong>Great!</strong> Your first scan is complete. Check your repository for the pull request.</p>
    </div>
  </div>
</div>
```

### AFTER (3 lines):
```heex
<.callout variant="success">
  <p><strong>Great!</strong> Your first scan is complete. Check your repository for the pull request.</p>
</.callout>
```

**Savings**: 73% reduction (11 → 3 lines)

---

## Callout Variants Available

The `Docs.Callout` component supports 5 variants:

```heex
<.callout variant="info" title="Optional Title">
  Information for users
</.callout>

<.callout variant="warning" title="Important">
  Warning or caution message
</.callout>

<.callout variant="error">
  Error or critical message
</.callout>

<.callout variant="success">
  Success or tip message
</.callout>

<.callout variant="note">
  General note (gray styling)
</.callout>
```

## Impact Across Support Pages

### Current Alert Usage (Estimated):
- onboarding.html.heex: ~4 alerts
- billing_faq.html.heex: ~8 alerts
- api_keys.html.heex: ~5 alerts
- credits.html.heex: ~4 alerts
- payment_troubleshooting.html.heex: ~4 alerts

**Total**: ~25 alert instances × 12 lines each = **300 lines**
**After refactoring**: ~25 × 3 lines = **75 lines**
**Reduction**: **225 lines saved** (75% reduction)

## Next Steps (If Approved)

1. Add `use RsolvWeb.Components.Docs` to support_html.ex
2. Find/replace alert patterns across all 6 templates
3. Test on staging to ensure styling matches
4. Deploy updated templates

**Estimated time**: 1-2 hours for all 25 instances

## Benefits

✅ **Consistency**: All alerts use the same Tailwind UI Plus styling
✅ **Maintainability**: Change alert styling in one place
✅ **Dark Mode**: Already handled correctly
✅ **Accessibility**: Proper ARIA attributes included
✅ **Battle-tested**: Used in docs.rsolv.dev
✅ **No new code**: Zero maintenance burden

---

**Recommendation**: This is a clear win. Use existing components before writing any new ones.
