# RFC-077: Tailwind Syntax Template Adoption for Documentation Site

**Status**: Draft
**Created**: 2025-10-24
**Phase**: 2
**Dependencies**: RFC-067 (GitHub Marketplace Publishing) - Implemented
**Related**: Task #5697 - Documentation Site (Phase 1 Complete)

## Quick Start

**Problem**: Current documentation site uses basic Tailwind styling without professional navigation UX or advanced accessibility features.

**Solution**: Adopt design patterns from Tailwind Plus Syntax template to enhance documentation site with professional components, keyboard navigation, and improved developer experience.

**Timeline**: 2-3 weeks
**Priority**: Medium (Post-launch enhancement)

## Summary

Phase 1 of the documentation site (Task #5697) successfully delivered 8 functional pages that meet GitHub Marketplace requirements. Phase 2 will enhance the site by adapting professional design patterns from the Tailwind Plus Syntax template, improving navigation UX, accessibility, and overall developer experience while maintaining the existing Phoenix/LiveView architecture.

## Problem

### Current State (Phase 1 - ✅ Complete)

**What Works Well:**
- ✅ All 8 documentation pages functional
- ✅ Dark mode compatible
- ✅ Mobile responsive
- ✅ SEO optimized (sitemap.xml)
- ✅ Clean Tailwind styling
- ✅ Meets RFC-067 requirements

**What Could Be Better:**
- Navigation is basic (back links only, no sidebar)
- No keyboard shortcuts for navigation
- Table of contents manually maintained
- Search not implemented
- Component styles inline in templates (not reusable)
- No advanced accessibility features
- Typography could be more polished
- Code blocks lack syntax highlighting

### Tailwind Plus Syntax Template

**What It Offers:**
- Professional navigation patterns (sidebar, mobile menu, breadcrumbs)
- Keyboard-accessible navigation (arrow keys, shortcuts)
- Advanced typography with Tailwind Typography plugin
- Reusable component library
- Comprehensive accessibility (ARIA labels, focus management)
- Modern developer-focused design
- Built by Tailwind CSS team (best practices)

**Technology Stack:**
- Next.js 15 + Markdoc (content authoring)
- React 19 components
- TypeScript 5.8
- Tailwind CSS 4.1

**Adaptation Challenge:**
- Template uses Next.js/React, we use Phoenix/LiveView
- Need to extract design patterns, not copy code directly
- Opportunity to create Phoenix-native components

## Solution

### Approach: Design Pattern Extraction

Rather than rewrite the site in Next.js, we'll **extract and adapt** the design patterns from Syntax template to Phoenix LiveView components.

**Key Patterns to Adopt:**

1. **Navigation Architecture**
   - Persistent sidebar with collapsible sections
   - Mobile hamburger menu
   - Breadcrumb navigation
   - Table of contents (auto-generated from headings)
   - Keyboard shortcuts (/, Cmd+K for search)

2. **Component Library**
   - Reusable LiveView components for docs pages
   - Code block component with syntax highlighting
   - Callout/Alert components (info, warning, error)
   - Link cards for navigation
   - Table components

3. **Typography System**
   - Tailwind Typography plugin configuration
   - Consistent heading hierarchy
   - Improved code/pre styling
   - Better list and table formatting

4. **Accessibility Enhancements**
   - Proper ARIA labels
   - Focus management for navigation
   - Skip links
   - Keyboard navigation
   - Screen reader improvements

5. **Developer Experience**
   - Auto-generated TOC from headings
   - Syntax highlighting in code blocks
   - Copy-to-clipboard for code examples
   - Search functionality (Phase 3)

### Implementation Phases

#### Phase 2A: Component Foundation (Week 1)

**Goal**: Create reusable LiveView components based on Syntax patterns

**Tasks:**
1. Create `lib/rsolv_web/components/docs/` directory structure
2. Extract layout patterns from Syntax template
3. Build core components:
   - `docs_layout.ex` - Sidebar + content layout
   - `sidebar_nav.ex` - Navigation tree component
   - `table_of_contents.ex` - Auto-generated from headings
   - `code_block.ex` - Syntax highlighted code
   - `callout.ex` - Info/warning/error boxes
   - `breadcrumbs.ex` - Navigation breadcrumbs

4. Configure Tailwind Typography plugin
5. Test components in isolation

**Deliverables:**
- Reusable LiveView components in `lib/rsolv_web/components/docs/`
- Updated `assets/tailwind.config.js` with Typography plugin
- Component storybook or demo page

#### Phase 2B: Navigation Enhancement (Week 2)

**Goal**: Implement professional navigation UX

**Tasks:**
1. Build sidebar navigation with collapsible sections
2. Add mobile hamburger menu
3. Implement breadcrumb trail
4. Add keyboard shortcuts (/, arrow keys)
5. Auto-generate table of contents from page headings
6. Add "Edit on GitHub" links
7. Implement "Next/Previous page" navigation

**Deliverables:**
- Functional sidebar with all 8 pages organized
- Mobile-responsive menu
- Keyboard navigation working
- TOC auto-generated for all pages

#### Phase 2C: Polish & Accessibility (Week 3)

**Goal**: Enhance typography, accessibility, and details

**Tasks:**
1. Apply Tailwind Typography styles to prose content
2. Add syntax highlighting to code blocks (highlight.js or Prism)
3. Implement copy-to-clipboard for code examples
4. Add ARIA labels and roles throughout
5. Improve focus management
6. Add skip links
7. Test with screen readers
8. Dark mode refinements

**Deliverables:**
- Professional typography throughout
- Syntax highlighted code blocks
- Full accessibility compliance
- Polished dark mode
- Copy-to-clipboard on code blocks

### Technical Architecture

#### Component Structure

```
lib/rsolv_web/
├── components/
│   └── docs/
│       ├── layout.ex           # Main docs layout with sidebar
│       ├── sidebar_nav.ex      # Navigation tree
│       ├── toc.ex              # Table of contents (auto-generated)
│       ├── code_block.ex       # Syntax highlighted code
│       ├── callout.ex          # Info/warning/error boxes
│       ├── breadcrumbs.ex      # Navigation breadcrumbs
│       ├── link_card.ex        # Navigation cards
│       └── page_nav.ex         # Next/Previous navigation
├── controllers/
│   ├── docs_controller.ex      # Existing controller (enhanced)
│   └── docs_html/
│       └── *.html.heex         # Existing pages (refactored to use components)
└── live/
    └── docs_search_live.ex     # Future: Live search (Phase 3)
```

#### Navigation Data Structure

```elixir
# lib/rsolv_web/docs_navigation.ex
defmodule RsolvWeb.DocsNavigation do
  @moduledoc "Documentation site navigation structure"

  def navigation_tree do
    [
      %{
        title: "Getting Started",
        items: [
          %{title: "Overview", path: "/docs", icon: "home"},
          %{title: "Installation", path: "/docs/installation", icon: "download"},
          %{title: "Getting Started", path: "/docs/getting-started", icon: "rocket"}
        ]
      },
      %{
        title: "Guides",
        items: [
          %{title: "Workflow Templates", path: "/docs/workflows", icon: "code"},
          %{title: "Configuration", path: "/docs/configuration", icon: "cog"}
        ]
      },
      %{
        title: "Reference",
        items: [
          %{title: "API Reference", path: "/docs/api-reference", icon: "book"},
          %{title: "Troubleshooting", path: "/docs/troubleshooting", icon: "wrench"},
          %{title: "FAQ", path: "/docs/faq", icon: "question"}
        ]
      }
    ]
  end

  def page_metadata(path) do
    # Auto-generate TOC, breadcrumbs, prev/next from navigation tree
  end
end
```

### Design Decisions

#### 1. LiveView Components vs React Components

**Decision**: Use Phoenix LiveView components, not React/Next.js

**Rationale**:
- Existing infrastructure is Phoenix/LiveView
- No need to introduce JavaScript framework complexity
- LiveView supports real-time updates (future search feature)
- Server-rendered components match existing architecture
- Easier to maintain with single tech stack

**Tradeoffs**:
- Can't copy Syntax template code directly (need to adapt)
- Some client-side features require JavaScript hooks
- LiveView learning curve for team (mitigated by existing usage)

#### 2. Static Navigation vs Dynamic Navigation

**Decision**: Static navigation tree in Elixir module

**Rationale**:
- Documentation structure rarely changes
- Compile-time validation of links
- No database queries needed
- Easy to update and version control

**Alternative Considered**: Database-driven navigation (rejected as overkill)

#### 3. Syntax Highlighting Approach

**Decision**: Use highlight.js with Alpine.js for client-side highlighting

**Rationale**:
- Works with server-rendered HTML
- No build step required
- Supports all relevant languages (YAML, Elixir, Ruby, etc.)
- Easy to add copy-to-clipboard feature
- Dark mode support built-in

**Alternative Considered**: Server-side highlighting with Chroma (rejected for simplicity)

#### 4. Table of Contents Generation

**Decision**: Auto-generate TOC from HTML headings using JavaScript

**Rationale**:
- No manual maintenance required
- Always stays in sync with page content
- Uses standard HTML heading structure
- Can highlight current section on scroll

**Implementation**:
```javascript
// assets/js/docs.js
export const DocsTOC = {
  mounted() {
    const headings = this.el.querySelectorAll('h2, h3');
    const toc = generateTOC(headings);
    this.el.innerHTML = toc;
    highlightCurrentSection();
  }
}
```

## Testing Strategy

### Component Testing

```elixir
# test/rsolv_web/components/docs/sidebar_nav_test.exs
defmodule RsolvWeb.Components.Docs.SidebarNavTest do
  use RsolvWeb.ConnCase, async: true
  import Phoenix.LiveViewTest

  test "renders navigation tree" do
    html = render_component(&RsolvWeb.Components.Docs.SidebarNav.render/1, %{
      current_path: "/docs/installation"
    })

    assert html =~ "Getting Started"
    assert html =~ "Installation"
    assert html =~ "aria-current=\"page\""
  end

  test "highlights current page" do
    # ...
  end

  test "supports keyboard navigation" do
    # ...
  end
end
```

### Accessibility Testing

```bash
# Install axe-core for accessibility testing
npm install --save-dev axe-core

# Run accessibility tests in browser
npm run test:a11y
```

### Visual Regression Testing

**Future Enhancement** (Phase 3):
- Use Percy.io or similar for visual regression
- Capture screenshots of each page in light/dark mode
- Detect unintended style changes

## Migration Path

### Incremental Rollout

**Week 1**: New components available but not yet used
**Week 2**: Migrate 2-3 pages to new components (test in staging)
**Week 3**: Migrate remaining pages, polish, deploy to production

**Rollback Plan**: Old templates remain available, can revert deployment

### Content Migration

Existing HEEx templates will be refactored to use new components:

**Before**:
```heex
<div class="min-h-screen bg-gradient-to-b from-slate-50 to-white dark:from-slate-900 dark:to-slate-800">
  <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
    <h1 class="text-4xl font-bold text-slate-900 dark:text-white mb-4">Installation Guide</h1>
    ...
  </div>
</div>
```

**After**:
```heex
<.docs_layout current_path={@current_path} page_title="Installation Guide">
  <.callout type="info">
    Prerequisites checklist before installation
  </.callout>

  <.code_block language="yaml" filename=".github/workflows/rsolv-security.yml">
    <%= @workflow_yaml %>
  </.code_block>
</.docs_layout>
```

## Success Metrics

### Phase 2 Completion Criteria

- [ ] All 8 documentation components created and tested
- [ ] Sidebar navigation functional on desktop and mobile
- [ ] Keyboard shortcuts working (/, arrow keys, Cmd+K placeholder)
- [ ] Table of contents auto-generated on all pages
- [ ] Syntax highlighting on all code blocks
- [ ] Copy-to-clipboard on code examples
- [ ] Accessibility score 95+ on Lighthouse
- [ ] Dark mode fully functional with new components
- [ ] All pages migrated to use new components
- [ ] Deployed to production without issues

### User Experience Improvements

**Measured by**:
- Time to find information (should decrease)
- Bounce rate on docs pages (should decrease)
- Pages per session (should increase)
- User feedback ("Was this helpful?" ratings)

## Risks & Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Components break existing pages | High | Medium | Incremental migration, thorough testing |
| Dark mode regressions | Medium | Medium | Visual regression tests, manual QA |
| Keyboard nav conflicts with browser | Medium | Low | Use uncommon shortcuts, allow customization |
| TOC generation fails on some pages | Medium | Low | Fallback to manual TOC, validate HTML structure |
| Syntax highlighting slow | Low | Low | Lazy load highlight.js, cache highlighted code |
| Accessibility regressions | High | Low | Automated a11y tests, screen reader testing |

## Future Work (Phase 3+)

### Search Functionality (RFC-078 - Future)

- **Client-side**: Algolia DocSearch or Lunr.js
- **Server-side**: PostgreSQL full-text search
- **LiveView**: Real-time search results

### Versioning (RFC-079 - Future)

- Version-specific documentation (e.g., `/docs/v3/`, `/docs/v4/`)
- Version switcher in navigation
- Maintain docs for last 2 major versions

### Interactive Examples (Future)

- Live code playground for YAML workflows
- Interactive configuration builder
- Real-time validation of workflow syntax

### Analytics Integration (Future)

- Track popular pages
- Monitor search queries
- Identify documentation gaps

## References

- [Tailwind Plus Syntax Template](https://tailwindcss.com/plus/templates/syntax)
- [Tailwind Plus Protocol Template](https://tailwindcss.com/plus/templates/protocol)
- [Phoenix LiveView Components](https://hexdocs.pm/phoenix_live_view/Phoenix.Component.html)
- [Tailwind Typography Plugin](https://tailwindcss.com/docs/typography-plugin)
- [RFC-067: GitHub Marketplace Publishing](RFC-067-GITHUB-MARKETPLACE-PUBLISHING.md)
- [Task #5697: Documentation Site (Phase 1)](https://linear.app/fitzgerald/issue/VIBE-5697)

## Appendix: Syntax Template Analysis

### Key Design Patterns Observed

1. **Three-column Layout**
   - Left: Collapsible sidebar navigation
   - Center: Main content with TOC
   - Right: Table of contents (desktop only)

2. **Navigation Patterns**
   - Hierarchical tree with expand/collapse
   - Visual indicators for current page
   - Breadcrumb trail at top
   - Next/Previous at bottom

3. **Typography**
   - Tailwind Typography prose classes
   - Consistent heading hierarchy
   - Code inline and blocks differentiated
   - Callouts for important info

4. **Accessibility**
   - Proper heading structure (h1 → h6)
   - ARIA labels on navigation
   - Focus indicators visible
   - Keyboard shortcuts documented

5. **Mobile Experience**
   - Hamburger menu for sidebar
   - TOC collapsed by default
   - Touch-friendly hit targets
   - Swipe gestures (optional)

### Color System

```css
/* Light mode */
--docs-bg: theme('colors.white');
--docs-text: theme('colors.slate.900');
--docs-border: theme('colors.slate.200');
--docs-accent: theme('colors.blue.600');

/* Dark mode */
--docs-bg-dark: theme('colors.slate.950');
--docs-text-dark: theme('colors.white');
--docs-border-dark: theme('colors.slate.800');
--docs-accent-dark: theme('colors.blue.400');
```

### Component Inventory

**From Syntax Template** → **Phoenix Equivalent**:
- `<Navigation>` → `sidebar_nav.ex`
- `<Prose>` → Tailwind Typography classes
- `<CodeBlock>` → `code_block.ex` with highlight.js
- `<TableOfContents>` → `toc.ex` with Alpine.js
- `<Breadcrumbs>` → `breadcrumbs.ex`
- `<Callout>` → `callout.ex`
- `<LinkCard>` → `link_card.ex`

---

**Next Steps**:
1. Approve RFC-077
2. Create Vibe Kanban task for Phase 2 (3-week sprint)
3. Begin component development (Week 1)
4. Incremental rollout (Week 2-3)
5. Launch enhanced docs site
