# Support Templates - DRY Refactoring Analysis

**Date:** 2025-11-04
**Status:** Analysis Complete - Refactoring Recommended

## Existing Component Libraries

After reviewing the codebase, we already have comprehensive component libraries:

### 1. Core Components (`lib/rsolv_web/components/core_components.ex`)
Phoenix-generated components with RSOLV customizations:
- `modal/1` - Modal dialogs
- `flash/1` & `flash_group/1` - Flash messages
- `button/1` - Styled buttons
- `input/1` - Form inputs (text, checkbox, select, textarea)
- `label/1` & `error/1` - Form helpers
- `header/1` - Page headers
- `table/1` - Data tables
- `list/1` - Description lists
- `back/1` - Back navigation link
- `icon/1` - Heroicons support

### 2. Docs Components (`lib/rsolv_web/components/docs/*.ex`)
Derived from Tailwind UI Plus for docs.rsolv.dev:
- **`callout/1`** - Alert/callout boxes (info, warning, error, success, note) ✨
- `breadcrumbs/1` - Breadcrumb navigation ✨
- `code_block/1` - Syntax-highlighted code blocks
- `docs_layout/1` - Full documentation layout with sidebar
- `sidebar_nav/1` - Hierarchical navigation menu
- `table_of_contents/1` - Auto-generated TOC

Usage: `use RsolvWeb.Components.Docs` imports all docs components

### 3. Landing Page Components
- `feature_card/1` - Feature highlight cards ✨
- `value_comparison/1` - Value proposition comparisons
- `theme_toggle/1` - Dark mode toggle
- `feedback_component/1` - User feedback forms

### 4. Utility Components
- `dark_mode_helpers.ex` - Helper functions for dark mode styling
- `header.ex` - Site-wide header
- `layouts.ex` - Application layouts

## Current Support Template Status

### What We Have
- **6 support templates**: index, onboarding, billing-faq, api-keys, credits, payment-troubleshooting
- **~4,500 total lines** across all templates
- **Inline styling**: All components defined inline with Tailwind classes

### Duplication Analysis

#### ✅ Components We CAN Reuse (Already Exist)

1. **Alert/Callout Boxes** → `Docs.Callout.callout/1`
   - Current: Custom inline alerts (~15 lines each, ~25 instances = 375 lines)
   - Replace with: Existing `callout` component with variants (info, warning, error, success)
   - **Savings**: ~350 lines

2. **Breadcrumb Navigation** → `Docs.Breadcrumbs.breadcrumbs/1`
   - Current: Custom "Back to Support" links (~12 lines × 5 pages = 60 lines)
   - Replace with: Existing breadcrumb component
   - **Savings**: ~45 lines

3. **Card Containers** → Can extend `feature_card` or create card variant
   - Current: FAQ cards, section cards (~5 lines × 80 instances = 400 lines)
   - Option: Create simple `card/1` component in CoreComponents
   - **Savings**: ~350 lines

#### ⚠️ Components We Should CREATE (Don't Exist Yet)

4. **Page Header with Title/Subtitle**
   - Current: Repeated pattern (~6 lines × 5 pages = 30 lines)
   - Create: Simple `support_header/1` component
   - **Savings**: ~20 lines

5. **Icon List Items**
   - Current: List items with checkmark icons (~8 lines × 150 instances = 1,200 lines)
   - Create: `icon_list_item/1` component with icon variants
   - **Savings**: ~1,000 lines

6. **Step Indicators**
   - Current: Numbered circles for steps (~6 lines × 10 instances = 60 lines)
   - Create: `step_number/1` component
   - **Savings**: ~40 lines

## Recommended Approach

### Phase 1: Use Existing Components (Low Effort, High Value)

Immediately refactor to use:
1. **`Docs.Callout.callout/1`** for all alert boxes
2. **`Docs.Breadcrumbs.breadcrumbs/1`** for navigation
3. **`CoreComponents.back/1`** for back links (if applicable)

**Impact**: ~400 lines saved, zero new code

### Phase 2: Create Minimal New Components (Medium Effort, Medium Value)

Add to `core_components.ex`:
```elixir
# Simple card wrapper
def card(assigns) do
  ~H"""
  <div class="bg-white dark:bg-slate-800 rounded-lg shadow-sm p-6 mb-4 border border-slate-200 dark:border-slate-700">
    <h3 :if={@title} class="text-lg font-semibold text-slate-900 dark:text-white mb-3">
      <%= @title %>
    </h3>
    <div class="text-slate-700 dark:text-slate-300 space-y-3">
      <%= render_slot(@inner_block) %>
    </div>
  </div>
  """
end

# Icon list item
def icon_list_item(assigns) do
  ~H"""
  <li class="flex items-start">
    <.icon name="hero-check-circle" class="w-5 h-5 text-blue-600 dark:text-blue-400 mr-2 mt-0.5 flex-shrink-0" />
    <span class="text-slate-700 dark:text-slate-300">
      <%= render_slot(@inner_block) %>
    </span>
  </li>
  """
end
```

**Impact**: ~1,300 lines saved, ~50 new lines

### Phase 3: Optional - Full Refactoring (High Effort, Diminishing Returns)

Create additional specialized components if needed. Consider whether the remaining duplication is worth the maintenance overhead.

## Implementation Plan

### Option A: Minimal Refactoring (Recommended)
1. Update `support_html.ex` to import docs components:
   ```elixir
   defmodule RsolvWeb.SupportHTML do
     use RsolvWeb, :html
     use RsolvWeb.Components.Docs  # Add this

     embed_templates "support_html/*"
   end
   ```

2. Replace inline alerts with `<.callout variant="info">` etc.
3. Add 2-3 helper components to `core_components.ex`
4. Refactor templates incrementally

**Effort**: 2-4 hours
**Impact**: ~1,500 lines saved (33% reduction)
**Risk**: Low - using battle-tested components

### Option B: No Refactoring (Also Valid)
Keep templates as-is because:
- Templates are working and deployed
- Duplication is localized to support pages
- Easy to find and modify patterns
- No immediate maintenance burden

**Effort**: 0 hours
**Risk**: None
**Trade-off**: Harder to maintain consistency across future support pages

## Recommendation

**Go with Option A** - Minimal refactoring using existing components:

1. ✅ **Now**: Import `Docs` components for immediate use
2. ✅ **Next week**: Add 2-3 simple helpers to CoreComponents
3. ✅ **Future**: Refactor templates as you touch them for updates

This gives us:
- 33% code reduction with minimal effort
- Consistent styling with existing RSOLV components
- No new component library to maintain
- Incremental, low-risk improvement path

## Components NOT to Create

Avoid creating these (diminishing returns):
- Section headings (simple enough inline)
- Step numbers (only 10 instances)
- Specialized layouts (templates are fine)
- One-off patterns (not worth componentizing)

## Next Steps

1. **Before committing**: Update `support_html.ex` to use docs components
2. **Quick win**: Replace 25 alert boxes with `<.callout>`
3. **Future**: Add `card/1` and `icon_list_item/1` to core_components when needed

---

**Key Insight**: We already have 90% of what we need. Don't build a new component library when we have excellent Tailwind UI-derived components ready to use!
