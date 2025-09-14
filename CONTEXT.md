# RSOLV Admin Login Debug Context

## Current Issue
Admin login fails on staging with Mnesia table not existing error.

### Error Details
- Authentication succeeds but fails when storing session token
- Error: `{:aborted, {:no_exists, :customer_sessions_mnesia}}`
- Location: lib/rsolv/customers.ex:309 in `generate_customer_session_token/1`

## Root Cause Analysis
The Mnesia table `customer_sessions_mnesia` is not being created on staging despite:
1. CustomerSessions being in the supervision tree (lib/rsolv/application.ex:40)
2. Table creation code exists in lib/rsolv/customer_sessions.ex

### Investigation Points
Looking at customer_sessions.ex:
- `setup_mnesia/0` called from `init/1` (line 24)
- Table creation happens in `ensure_table_exists/0` (line 228)
- May be failing silently or timing out

## Recent Fixes Applied
1. **Pattern Matching Fix**: Changed `{:atomic, :ok}` to `{:atomic, _result}` in customers.ex:309
2. **JavaScript Redirect**: Added push_event with Redirect hook for LiveView navigation
3. **Hook Attachment**: Added phx-hook="Redirect" to admin-login div

## Todo List
- [x] Test admin login on staging environment
- [ ] Fix Mnesia table initialization on staging
- [ ] Run comprehensive local tests to verify the fix

## Testing Credentials
- URL: https://rsolv-staging.com/admin/login
- Email: admin@rsolv.com
- Password: AdminP@ss123!

## Key Files
- `/lib/rsolv/customer_sessions.ex` - Mnesia table management
- `/lib/rsolv/customers.ex` - Session token generation
- `/lib/rsolv_web/live/admin/login_live.ex` - Login LiveView
- `/assets/js/app.js` - JavaScript redirect hook
- `/lib/rsolv/application.ex` - Supervision tree

## Next Steps
1. Check Mnesia initialization logs on staging
2. Add better error handling and logging to table creation
3. Consider adding retry logic for table creation
4. Verify Mnesia directory permissions in container