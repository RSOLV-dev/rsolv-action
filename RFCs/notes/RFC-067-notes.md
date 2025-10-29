# RFC-067 notes

## Solution
### Required Updates to action.yml

Name: let's go with something more like "RSOLV AI Vulnerability Resolver" or similarly tight and punch. And ensure we track this change into our description.
inputs.rsolvApiKey.description -- is the URI here correct and available?
mode.description: note that these listed modes operate somewhat differently. 'scan' operates across the full repo. The others operate on individual GH issues. You'll want to look over the architecture of each phase to fully understand how they work so that we can more accurately describe them and their use cases. We might have to change the structure of 'mode' here entirely, or even split it into multiple workflows.

### README Requirements

In code block:
```
- ** 🔍 Smart Detection** - AST-based vulnerability scanning with minimal false positives
```
"Minimal false positives" is pretty vague. Can we be more specific about what this means in practice? Or can we highlight the tech behind this and why it's better than other tools? Also note the author's credentials as actually writing not-shitty tests.

```
- **Existing Customers##: Get key from dashboard**```
Does that URI exist, or will it after our work? If we do indeed need this now, that might mean revisiting the decision to have an API management page only later in RFC-070+ and instead that we'll need at least a barebones customer dashboard earlier. I'm open to that; let's think it through.

And also inline in the code block, we have an example manual setup for scheduling scan weekly. This raises a good point--do we have any rate limiting on our scan (or other!) APIs, even once authenticated? If so, we should document that here so users understand the limits of what they can do with the API key. If not, we should implement _something_. We have other rate limiting within the app, so we can reuse the pattern. And these APIs aren't expensive, but nor are they free; we don't want to crash our app.

Also, the default for `jobs.security.steps.with.mode` probably sholdn't be `full`. THAT is a lot of work. Customers could potentially blow their entire credit balance without a chance to have input on what they want to prioritize.

## License

Immediately following the License verbiage, we have a bunch of stuff (implementation tasks and schedule, marketplace metadata) in a code block that appears as though it shouldn't be in one.

## End-to-End Testing with Real Repositories

Note that NodeGoat and Rails Goat both have _documented_ real vulnerabilities. We can and should cross-check those docs against what we find with RSOLV to ensure we're catching known issues. There'll be misses--there's things in both repos we're not yet looking for--but if there's misses _within categories that we're scanning for_, that's something we should address.

## STaging vs Dev vs CI Environments

Reference to staging RSOLV_API_URL is incorrect. It should be https://rsolv-staging.com/api or similar. staging-api.rsolv.dev is not correct; since we CNAME *.rsolv.dev to rsolv.dev we'll just call the prod API.

## Risks & Mitigation
### Critical Risk: Market Silence
*Mitigation Strategy - Multi-Channel Go-To-Market*: We should also include outreach to folks in my warm network that'd actually use this product. Ask them to kick the tires. Give 'em free credits. Get feedback. This is low-cost and high-value.

*Direct Outreach* Note that we don't have anyone on the waiting list.

# Support Infrastructure Validation
## Documenation Site
Does this exist at all?
