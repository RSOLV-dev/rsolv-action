# Documentation Site Components - Implementation Summary

## Overview

This document describes the new documentation site components built for RSOLV, implementing Phase 2A of RFC-077 (Tailwind Syntax Template Adoption). These components provide a professional, accessible, and developer-friendly documentation experience.

## Date Created

2025-10-28

## Components Implemented

### 1. Navigation Module (`lib/rsolv_web/components/docs/navigation.ex`)

**Purpose**: Defines the hierarchical documentation structure and provides navigation utilities.

**Key Functions**:
- `navigation_tree/0` - Returns the complete navigation structure
- `all_pages/0` - Flattened list of all pages
- `find_adjacent_pages/1` - Gets previous/next pages for navigation
- `breadcrumbs/1` - Generates breadcrumb trail
- `current_page?/2` - Determines if a page is active

**Navigation Structure**:
```elixir
[
  %{
    title: "Getting Started",
    icon: "...",
    pages: [
      %{title: "Introduction", href: "/docs", description: "..."},
      %{title: "Installation", href: "/docs/installation", description: "..."},
      %{title: "Getting Started", href: "/docs/getting-started", description: "..."}
    ]
  },
  # ... more sections
]
```

### 2. DocsLayout Component (`lib/rsolv_web/components/docs/docs_layout.ex`)

**Purpose**: Main layout wrapper that orchestrates all documentation page elements.

**Features**:
- ✅ Responsive sidebar navigation (desktop + mobile hamburger menu)
- ✅ Breadcrumb trail
- ✅ Theme toggle
- ✅ Auto-generated table of contents
- ✅ Previous/Next page navigation
- ✅ "Edit on GitHub" link
- ✅ Keyboard shortcuts (/ key reserved for search)

**Usage**:
```heex
<.docs_layout current_path="/docs/installation">
  <h1 id="installation">Installation</h1>
  <p>Content here...</p>
</.docs_layout>
```

**Attributes**:
- `current_path` (required) - Current page path for active state
- `show_toc` (default: true) - Display table of contents
- `toc_headings` (optional) - Manual TOC headings
- `show_breadcrumbs` (default: true) - Display breadcrumbs
- `show_nav_footer` (default: true) - Display prev/next navigation
- `class` - Additional CSS classes

### 3. SidebarNav Component (`lib/rsolv_web/components/docs/sidebar_nav.ex`)

**Purpose**: Hierarchical navigation menu with sections and pages.

**Features**:
- ✅ Collapsible sections
- ✅ Active page highlighting
- ✅ Mobile-responsive (hidden on mobile, toggled via hamburger)
- ✅ Support links (GitHub Issues, Email Support)
- ✅ RSOLV logo/home link

**Usage**:
```heex
<.sidebar_nav current_path="/docs/installation" />
```

### 4. TableOfContents Component (`lib/rsolv_web/components/docs/table_of_contents.ex`)

**Purpose**: Auto-generated or manual table of contents with active section highlighting.

**Features**:
- ✅ Auto-generates TOC from h2/h3 headings
- ✅ Smooth scroll to sections
- ✅ Highlights current section on scroll (IntersectionObserver)
- ✅ Sticky positioning
- ✅ Desktop only (hidden on mobile/tablet)

**Usage**:
```heex
<!-- Auto-generated -->
<.table_of_contents container_id="doc-content" />

<!-- Manual -->
<.table_of_contents headings={[
  %{id: "installation", title: "Installation", level: 2},
  %{id: "setup", title: "Setup", level: 3}
]} />
```

### 5. Breadcrumbs Component (`lib/rsolv_web/components/docs/breadcrumbs.ex`)

**Purpose**: Breadcrumb navigation showing page hierarchy.

**Features**:
- ✅ Auto-generated from navigation structure
- ✅ Accessible (aria-label, aria-current)
- ✅ Responsive styling

**Usage**:
```heex
<.breadcrumbs current_path="/docs/installation" />
```

**Output**: `Documentation > Installation`

### 6. CodeBlock Component (`lib/rsolv_web/components/docs/code_block.ex`)

**Purpose**: Syntax-highlighted code blocks with copy functionality.

**Features**:
- ✅ Syntax highlighting (via CSS classes, ready for highlight.js)
- ✅ Copy to clipboard button
- ✅ Optional filename header
- ✅ Optional line numbers
- ✅ Dark theme (slate-900 background)
- ✅ Visual feedback on copy (checkmark animation)

**Usage**:
```heex
<.code_block language="elixir">
defmodule Example do
  def hello, do: "world"
end
</.code_block>

<.code_block language="yaml" filename=".github/workflows/rsolv.yml">
name: RSOLV Security
on: [push]
</.code_block>
```

**Important**: Code content with special characters (like `${{ }}` in YAML) should be wrapped in `<%= """ ... """ %>` or `<%= ~S""" ... """ %>` to prevent HEEx interpolation:

```heex
<.code_block language="yaml"><%= """
api-key: ${{ secrets.API_KEY }}
""" %></.code_block>
```

### 7. Callout Component (`lib/rsolv_web/components/docs/callout.ex`)

**Purpose**: Highlighted boxes for important information, warnings, tips, etc.

**Features**:
- ✅ 5 variants: info, warning, error, success, note
- ✅ Optional title
- ✅ Accessible (role="note")
- ✅ Dark mode support
- ✅ Appropriate icons for each variant

**Usage**:
```heex
<.callout>
  Default info callout
</.callout>

<.callout variant="warning" title="Important">
  Make sure to backup your data!
</.callout>

<.callout variant="error">
  This operation cannot be undone.
</.callout>

<.callout variant="success">
  Installation complete!
</.callout>

<.callout variant="note">
  This is a general note.
</.callout>
```

## Using the Components

### 1. Import in Your Template Module

```elixir
defmodule RsolvWeb.DocsHTML do
  use RsolvWeb, :html
  use RsolvWeb.Components.Docs  # <-- Add this line

  embed_templates "docs_html/*"
end
```

This imports all component functions directly, allowing you to use `<.docs_layout>`, `<.callout>`, etc.

### 2. Create a Documentation Page

Create a new `.html.heex` file in `lib/rsolv_web/controllers/docs_html/`:

```heex
<.docs_layout current_path="/docs/my-page">
  <h1 id="my-page">My Page Title</h1>

  <p class="lead">
    Introduction paragraph with larger text.
  </p>

  <.callout variant="info" title="What you'll learn">
    <ul>
      <li>Point 1</li>
      <li>Point 2</li>
    </ul>
  </.callout>

  <h2 id="section-1">Section 1</h2>
  <p>Content here...</p>

  <.code_block language="elixir">
  defmodule Example do
    def hello, do: "world"
  end
  </.code_block>

  <h3 id="subsection">Subsection</h3>
  <p>More content...</p>

  <.callout variant="success" title="Pro Tip">
    Use keyboard shortcuts for faster navigation!
  </.callout>
</.docs_layout>
```

### 3. Add the Page to Navigation

Update `lib/rsolv_web/components/docs/navigation.ex` to include your new page:

```elixir
%{
  title: "Your Section",
  icon: "M...",
  pages: [
    %{
      title: "My Page",
      href: "/docs/my-page",
      description: "Short description"
    }
  ]
}
```

### 4. Add Route (if needed)

If creating a new page, add a route in `lib/rsolv_web/router.ex`:

```elixir
scope "/docs", RsolvWeb do
  pipe_through :browser

  get "/my-page", DocsController, :my_page
end
```

And add the controller action in `lib/rsolv_web/controllers/docs_controller.ex`:

```elixir
def my_page(conn, _params) do
  render(conn, :my_page, page_title: "My Page - RSOLV")
end
```

## Best Practices

### Heading Structure
- Use `h1` for page title (only one per page)
- Use `h2` for main sections
- Use `h3` for subsections
- Always add `id` attributes for TOC generation: `<h2 id="section-name">Section Name</h2>`

### Accessibility
- All headings have meaningful IDs
- Breadcrumbs use `aria-label` and `aria-current`
- Navigation uses `aria-label` and `aria-current`
- Callouts use `role="note"`
- Code copy button has `aria-label`
- Mobile menu button has `aria-label`

### Dark Mode
All components are fully compatible with dark mode:
- Use Tailwind's `dark:` prefix for styles
- Colors use semantic slate/blue palette
- Test both themes before committing

### Typography
The layout uses Tailwind Typography plugin (`prose` class):
- Applied to `<article>` tag in docs_layout
- Handles spacing, sizing, and styling for markdown-like content
- Use `prose-slate` for color scheme
- Use `dark:prose-invert` for dark mode

### Mobile Responsiveness
- Sidebar hidden on mobile, accessible via hamburger menu
- TOC hidden on mobile/tablet (< xl breakpoint)
- Breadcrumbs responsive (stack on small screens)
- Code blocks scroll horizontally on overflow

## Styling Guidelines

### Color Palette
- **Primary**: `blue-600` / `blue-400` (dark mode)
- **Text**: `slate-900` / `white` (dark mode)
- **Secondary Text**: `slate-600` / `slate-300` (dark mode)
- **Borders**: `slate-200` / `slate-700` (dark mode)
- **Backgrounds**: `white` / `slate-900` (dark mode)

### Spacing
- Section spacing: `mb-8` (2rem)
- Paragraph spacing: `mb-4` (1rem)
- Component spacing: `space-y-2` to `space-y-8` depending on hierarchy

### Border Radius
- Cards/boxes: `rounded-lg` (0.5rem)
- Buttons: `rounded-lg` or `rounded-md`
- Pills/badges: `rounded-full`

## JavaScript Functionality

### Mobile Navigation Toggle
```javascript
window.toggleMobileNav = function() {
  const nav = document.getElementById('mobile-nav');
  const overlay = document.getElementById('mobile-nav-overlay');
  nav.classList.toggle('hidden');
  overlay.classList.toggle('hidden');
};
```

### Copy Code to Clipboard
```javascript
window.copyCode = function(id) {
  const codeBlock = document.getElementById(id);
  const code = codeBlock.textContent;
  navigator.clipboard.writeText(code).then(() => {
    // Show check icon for 2 seconds
  });
};
```

### TOC Auto-Generation & Highlighting
- Uses `IntersectionObserver` to detect visible headings
- Highlights corresponding TOC link when section is in viewport
- Smooth scroll when clicking TOC links (native browser behavior)

## File Structure

```
lib/rsolv_web/components/
├── docs.ex                              # Main module for importing all components
└── docs/
    ├── navigation.ex                    # Navigation structure and utilities
    ├── docs_layout.ex                   # Main layout wrapper
    ├── sidebar_nav.ex                   # Sidebar navigation menu
    ├── table_of_contents.ex             # Auto-generated TOC
    ├── breadcrumbs.ex                   # Breadcrumb navigation
    ├── code_block.ex                    # Code blocks with copy
    └── callout.ex                       # Info/warning/error boxes

lib/rsolv_web/controllers/
├── docs_controller.ex                   # Route handlers
├── docs_html.ex                         # Template module
└── docs_html/
    ├── index.html.heex                  # Docs home page
    ├── installation.html.heex           # Installation guide
    ├── getting_started.html.heex        # Getting started tutorial
    ├── example_new_layout.html.heex     # Example using new components
    └── ...                              # Other documentation pages
```

## Example Page

See `lib/rsolv_web/controllers/docs_html/example_new_layout.html.heex` for a complete example demonstrating all components.

## Testing

1. **Compilation**: `mix compile` - Ensure all components compile without errors
2. **Visual Testing**: Start server with `mix phx.server` and visit `/docs/example`
3. **Responsive Testing**: Test mobile hamburger menu, tablet layout, desktop sidebar
4. **Dark Mode**: Toggle theme and verify all components render correctly
5. **Accessibility**: Test with screen reader, keyboard navigation
6. **Code Copy**: Click copy buttons on code blocks
7. **TOC**: Scroll page and verify active section highlighting

## Next Steps (Phase 2B - Week 2)

The following features are planned for Phase 2B:

- [ ] Implement keyboard shortcuts (/ for search, arrow keys for navigation)
- [ ] Add syntax highlighting with highlight.js
- [ ] Enhance mobile hamburger menu with animation
- [ ] Add search functionality
- [ ] Implement collapsible navigation sections
- [ ] Add "Jump to top" button
- [ ] Improve focus management and skip links

## Known Limitations

1. **Syntax Highlighting**: Code blocks have CSS classes ready for highlight.js, but the library is not yet integrated. Colors will be monochrome until highlight.js is added.

2. **Line Numbers**: The `show_line_numbers` attribute on code blocks is implemented but not fully styled. This will be completed in Phase 2B.

3. **Search**: The keyboard shortcut (/) is reserved for search, but search functionality is not yet implemented.

4. **Section Collapsing**: Navigation sections in the sidebar are always expanded. Collapsible sections will be added in Phase 2B.

## Migration Guide

To migrate existing documentation pages to use the new components:

1. **Wrap in `<.docs_layout>`**:
   ```heex
   <.docs_layout current_path="/docs/your-page">
     <!-- existing content -->
   </.docs_layout>
   ```

2. **Replace callout boxes** with `<.callout>` component:
   ```heex
   <!-- Before -->
   <div class="bg-blue-50 border border-blue-200 ...">
     Important info
   </div>

   <!-- After -->
   <.callout variant="info" title="Important">
     Important info
   </.callout>
   ```

3. **Replace code blocks** with `<.code_block>`:
   ```heex
   <!-- Before -->
   <pre><code class="language-elixir">
   defmodule Example do
     def hello, do: "world"
   end
   </code></pre>

   <!-- After -->
   <.code_block language="elixir">
   defmodule Example do
     def hello, do: "world"
   end
   </.code_block>
   ```

4. **Add IDs to headings** for TOC:
   ```heex
   <h2 id="installation">Installation</h2>
   <h3 id="setup">Setup</h3>
   ```

5. **Update navigation** in `navigation.ex` if needed.

## Support

For questions or issues with the documentation components:
- See example usage in `example_new_layout.html.heex`
- Check component module docs (`@doc` strings)
- Refer to this README
- Contact the development team

## Changelog

### 2025-10-28 - Phase 2A Complete
- ✅ Created 7 core documentation components
- ✅ Implemented navigation structure
- ✅ Built responsive layout with sidebar and TOC
- ✅ Added breadcrumbs and prev/next navigation
- ✅ Created code blocks with copy functionality
- ✅ Implemented callout boxes with 5 variants
- ✅ Added dark mode support throughout
- ✅ Ensured accessibility (ARIA labels, semantic HTML)
- ✅ Compiled successfully without errors
- ✅ Created example page demonstrating all features
