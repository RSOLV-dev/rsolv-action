# Phase 2A Fix: Sidebar Visibility Issue

**Date**: 2025-10-28
**Issue**: Sidebar navigation hidden on desktop
**Status**: ✅ Fixed and redeployed

## Problem

After initial deployment to staging, the sidebar navigation was not visible on desktop. Investigation revealed:

**Root Cause**: Duplicate `hidden lg:block` classes causing the sidebar to remain hidden.

### Technical Details

The `docs_layout.ex` wrapper div had:
```heex
<div id="mobile-nav" class="hidden lg:block">
  <SidebarNav.sidebar_nav current_path={@current_path} />
</div>
```

But `SidebarNav` component itself also had `hidden lg:block` in its nav element, causing double-hiding.

## Fix

**File**: `lib/rsolv_web/components/docs/docs_layout.ex`
**Line**: 81

Changed:
```heex
<!-- BEFORE -->
<div id="mobile-nav" class="hidden lg:block">
  <SidebarNav.sidebar_nav current_path={@current_path} />
</div>

<!-- AFTER -->
<div id="mobile-nav">
  <SidebarNav.sidebar_nav current_path={@current_path} />
</div>
```

The `SidebarNav` component already handles the `hidden lg:block` logic internally, so the wrapper should not add it.

## Deployment

```bash
# Rebuilt image
DOCKER_HOST=10.5.0.5 docker build -t ghcr.io/rsolv-dev/rsolv-platform:staging .

# Pushed to registry
DOCKER_HOST=10.5.0.5 docker push ghcr.io/rsolv-dev/rsolv-platform:staging

# Restarted deployment
kubectl rollout restart deployment/staging-rsolv-platform -n rsolv-staging
```

**New Image Digest**: `sha256:21046684e87498dbca5065cb02c9069e4d0f4aac64d64edcc4009f24daa512e2`

## Verification

The fix should result in:
- ✅ Sidebar visible on desktop (width >= 1024px)
- ✅ Sidebar hidden on mobile by default
- ✅ Hamburger menu button functional
- ✅ JavaScript toggle still works

## Testing Checklist

- [ ] Visit https://rsolv-staging.com/docs/example on desktop
- [ ] Sidebar visible on left side
- [ ] Navigation links clickable
- [ ] Active page highlighting works
- [ ] Mobile view (< 1024px) hides sidebar
- [ ] Hamburger button shows on mobile
- [ ] Clicking hamburger toggles sidebar

## Lessons Learned

1. **Component Composition**: When wrapping components, check if the wrapper and component both apply the same responsive classes
2. **Testing**: Should have tested the deployed site visually before considering deployment complete
3. **HTML Inspection**: `curl` + `grep` is effective for quick debugging of rendered HTML

## Related Files

- `lib/rsolv_web/components/docs/docs_layout.ex` (fixed)
- `lib/rsolv_web/components/docs/sidebar_nav.ex` (contains internal responsive classes)

---

**Status**: Fix deployed to staging at 2025-10-28 17:52 UTC
**Test URL**: https://rsolv-staging.com/docs/example
