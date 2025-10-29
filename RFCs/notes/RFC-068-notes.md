# RFC-068 Notes

## Summary
In addition to the verbiage here, let's include also using Tailscale as appropriate to make testing, dev more straightforward. We already have it installed and configured on most devices and it's very useful for remote access.

Also, note that we have Docker and k8s access.

## Testing Architecture

Both flow diagrams here are unintuitive. They look like a flow, but what it is that's flowing?

Also, worth noting: staging is already in k8s. We can also spin up new envs/namespaces/whatever in k8s if that's helpful for testing. It might just be overcomplicated, but we do have the option. We've got k8s access with your k8s MCP and via kubectl. Cf RSOLV-infrastructure/ contents. We don't want to create a large technical burdern, though.

## Monitoring & Telemetry Testing Patterns
### Implementation Pattern

Quick check: is `:telemetry.execute/3` etc OpenTelemetry or something else?

### Dashboard Creation

Let's also note at the end of this section that after creation, we need to verify and validate functionality. We can use API access, Puppeteer, and other tools at our disposal to check the dashboard, create and emit some events, then ensure the dashboard captures those and reflects them correctly.

## Docker Compose Setup

We note `bamboo_postmark`, and rightly so--but is it exposed for our use? Is that documented?

## Testing Standards & Patterns

100% coverage is nice for webhook handlers, but 80% coverage is acceptable across the board; the balane here is that we don't want to start having to adjust our implementation to hit coverage targets, or tying ourselves in knots. We _do_ need to prove that our code works, and higher coverage is desirable if it doesn't come at a cost.

Also, a reminder that doctests are great, and count towards coverage (and we should absolutely ensure ExCoveralls is configured to include them).

## Teseting Primciples

Before we ship, we also need e2e/system tests.

## Factory Traits / Seed Data Strategy

### Staging Environment Reset

I'm not sure we have `mix` on staging; it's probably a production-shaped environment, and as such an Erlang release. We may need to use RPCs or rethink how this would work.

### Data poollution prevention

Usage of @test.com is a smell. That domain is public and available for sale. Use example.com or test.example.com.

### Coverage Requirements

100% coverage is a smell. As discussed above, 80% is a floor, 95% is a good target, balance is key.

Re: "Test Reliability": this is CRUCIAL. We accept _zero_ flaky tests. Not <1%. ZERO. They're way more costly and confusing over time than a mere failing test.
