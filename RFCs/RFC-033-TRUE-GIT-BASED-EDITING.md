# RFC-033: True Git-Based Editing Implementation

**Status**: Draft  
**Created**: June 28, 2025  
**Author**: Infrastructure Team  

## Summary

Implement true git-based editing that uses actual git commands (`git apply`, `git diff`) instead of simulating git behavior. This ensures perfect fidelity with git's actual behavior and eliminates edge cases.

## Motivation

ADR-012 introduced git-based in-place editing as a configuration option to prevent PRs from creating new files instead of modifying existing ones. The current implementation simulates git behavior by:
1. Creating a temporary git repository
2. Copying files to it
3. Applying changes
4. Generating diffs

While this works well, true git-based editing would:
- Eliminate simulation edge cases
- Use git's native diff parsing and application
- Provide better error messages from git itself
- Enable more advanced git operations (partial hunks, etc.)

## Detailed Design

### 1. Replace Simulation with Native Git

Instead of simulating git behavior, use actual git commands:

```typescript
// Current (simulated)
const tempRepo = await createTempGitRepo();
await copyFilesToTemp(files, tempRepo);
const patches = await generatePatches(changes);

// Proposed (native git)
const patches = await generateGitPatches(changes);
await exec(`git apply --check ${patchFile}`);
await exec(`git apply ${patchFile}`);
```

### 2. Git Patch Generation

Generate proper git-formatted patches:

```typescript
interface GitPatch {
  generatePatch(change: FileChange): string {
    const patch = [
      `diff --git a/${change.path} b/${change.path}`,
      `index ${change.oldHash}..${change.newHash} 100644`,
      `--- a/${change.path}`,
      `+++ b/${change.path}`,
      this.generateHunks(change),
    ].join('\n');
    
    return patch;
  }
}
```

### 3. Integration Points

Update the git-based processor to use native git:

```typescript
export async function processIssueWithGit(
  issue: Issue,
  config: Config
): Promise<ProcessingResult> {
  const workspace = await prepareGitWorkspace(issue.repository);
  
  try {
    // Generate patches from AI suggestions
    const patches = await generatePatches(issue.fixes);
    
    // Validate patches
    for (const patch of patches) {
      await validateGitPatch(patch, workspace);
    }
    
    // Apply patches
    const results = await applyGitPatches(patches, workspace);
    
    // Create PR with applied changes
    return createPullRequest(results, issue);
  } finally {
    await cleanupWorkspace(workspace);
  }
}
```

### 4. Error Handling

Leverage git's error messages:

```typescript
async function applyGitPatch(patch: string, workspace: string): Promise<void> {
  try {
    await exec(`git apply --check`, { input: patch, cwd: workspace });
    await exec(`git apply`, { input: patch, cwd: workspace });
  } catch (error) {
    if (error.message.includes('patch does not apply')) {
      throw new PatchConflictError(
        'Git patch conflicts detected',
        extractConflictDetails(error)
      );
    }
    throw error;
  }
}
```

### 5. Advanced Features

Enable advanced git operations:

```typescript
interface AdvancedGitOperations {
  // Apply only specific hunks
  applySelectiveHunks(patch: GitPatch, hunks: number[]): Promise<void>;
  
  // Three-way merge for conflicts
  threeWayMerge(base: string, ours: string, theirs: string): Promise<string>;
  
  // Interactive patch editing
  interactivePatchEdit(patch: GitPatch): Promise<GitPatch>;
}
```

## Implementation Plan

### Phase 1: Core Git Integration (Week 1)
- [ ] Replace temp repo simulation with git commands
- [ ] Implement git patch generation
- [ ] Add git apply validation
- [ ] Update error handling

### Phase 2: Testing & Migration (Week 2)
- [ ] Comprehensive test suite for git operations
- [ ] Parallel testing with existing implementation
- [ ] Performance benchmarking
- [ ] Migration plan for existing features

### Phase 3: Advanced Features (Week 3)
- [ ] Selective hunk application
- [ ] Conflict resolution strategies
- [ ] Interactive patch editing
- [ ] Git-based rollback capabilities

## Alternatives Considered

1. **Keep Current Simulation**: Works well but may have edge cases
2. **LibGit2 Integration**: More complex, requires native bindings
3. **Git CLI Wrapper Library**: Adds dependency, may not cover all needs

## Success Metrics

1. **Zero PR Creation Failures**: No new files created when modifying existing
2. **Git Compatibility**: 100% compatibility with git's patch format
3. **Performance**: No degradation vs current implementation
4. **Error Quality**: Better error messages from native git

## Risks and Mitigations

1. **Risk**: Git CLI availability in different environments
   - **Mitigation**: Fallback to simulation mode, clear error messages

2. **Risk**: Performance overhead of spawning git processes
   - **Mitigation**: Batch operations, process pooling

3. **Risk**: Git version compatibility
   - **Mitigation**: Test against multiple git versions, use stable features

## References

- [ADR-012: In-Place Vulnerability Fixes](../ADRs/ADR-012-IN-PLACE-VULNERABILITY-FIXES.md)
- [Git Apply Documentation](https://git-scm.com/docs/git-apply)
- [Git Patch Format Specification](https://git-scm.com/docs/git-format-patch)