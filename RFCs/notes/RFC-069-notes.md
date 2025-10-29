# RFC-069 notes

## Integration Data Flow
### Customer Onboarding Flow
Re: rsolv.dev/register: did we update/cascade this RFC to /signup to harmonize with the changes in sibling RFCs? Ensure we're consistent.

Sequence diagrams: `source: 'marketplace'` -- let's be more specific like `gh_marketplace`; we may be on other marketplaces down the line.

### Usage Tracking Flow
- we'll eventually need more intelligence around how to trigger track_fix_deployed. This is an easy thing for customers to work around currently, and we'd end up significantly underbilling.
re: "record usage (if PAYG/Pro)" -- what if they're not PAYG/Pro? What's the flow then?

## Data Contracts
Note that we already have OpenApiSpex or similar in place, so there's some infra and support for OpenAPI usage.

In all the subsctions here, we should review all contract definitions against our revised sibling RFCs 064 through 068 to ensure consistency. We've made changes there and they may affect some or all contracts here.

## Continuous Integation Plan (TDD Focus)

We should eliminate any discussion of meetings or kickoffs; this is a tiny team and we'll be in sync.

### Thursday: Load Testing

Are there Elixir-based options for load testing so we can stay consistent in our language family? If they're not mature and well-documented, your selected tools are fine. Using JS and Python with LLMs is straightforward.

### Friday: Production Preparation

"We launch directly into production". True, but we do stage onto staging and test there first.

## Rollback Strategy

You note both feature flags and killswitches. Do we need both? Should we use FF's for the use case for which we describe killswitches? Or do we want to be dead certain it'll work and not rely on an external library?

## Risk Areas & Mitigation

mitigation for "Customers don't show up" -- let's create a tracking doc with todos and review every weekday while this RFC is in flight and until we're seeing traction.

## Communication Plan

We can also include a tracking doc (as described in Risk Areas & Mitigation), and we can use Vibe Kanban; we'll be using the latter for actual task management at time too.

In the working agreement, also add:
* ADR(s) upon each RFC completion to document all architecture decisions

## Success Criteria -> Must Have:
"All tests passing (>90% coverage)" -- let's adjust to ">80% coverage" as discussed elsewhere. Balance is key.
