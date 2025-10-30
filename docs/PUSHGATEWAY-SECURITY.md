# Pushgateway Security Configuration

## Authentication

The Pushgateway endpoint (`https://pushgateway.rsolv.dev`) is protected with HTTP Basic Authentication to prevent unauthorized metric submissions.

### Initial Setup (One-time per environment)

**Prerequisites:**
- `htpasswd` utility (from `apache2-utils` package on Ubuntu/Debian, or `httpd-tools` on RHEL/CentOS)
- `kubectl` access to the target namespace

**Steps:**

1. **Generate the auth file:**
   ```bash
   # Create a username/password pair
   # Replace 'github-actions' with desired username
   # You'll be prompted for the password
   htpasswd -c auth github-actions
   ```

2. **Create the Kubernetes secret:**
   ```bash
   # For staging
   kubectl create secret generic pushgateway-auth \
     --from-file=auth \
     -n rsolv-monitoring-staging

   # For production
   kubectl create secret generic pushgateway-auth \
     --from-file=auth \
     -n rsolv-monitoring
   ```

3. **Store credentials securely:**
   - Add the username/password to GitHub repository secrets:
     - `PUSHGATEWAY_USERNAME` - the username (e.g., `github-actions`)
     - `PUSHGATEWAY_PASSWORD` - the password
   - **Important:** The password should be a strong random string, not a human-memorable password

4. **Clean up the local auth file:**
   ```bash
   rm auth
   ```

### GitHub Actions Configuration

Update workflows to use authenticated requests:

```yaml
- name: Export metrics to Prometheus
  if: env.PUSHGATEWAY_URL != ''
  env:
    PUSHGATEWAY_USERNAME: ${{ secrets.PUSHGATEWAY_USERNAME }}
    PUSHGATEWAY_PASSWORD: ${{ secrets.PUSHGATEWAY_PASSWORD }}
  run: |
    WORKFLOW_ENCODED=$(echo "${GITHUB_WORKFLOW}" | sed 's/ /%20/g')
    cat <<EOF | curl --user "${PUSHGATEWAY_USERNAME}:${PUSHGATEWAY_PASSWORD}" --data-binary @- ${PUSHGATEWAY_URL}/metrics/job/ci/workflow/${WORKFLOW_ENCODED}
    # ... metrics ...
    EOF
```

### Rotating Credentials

To rotate the Pushgateway password:

1. Generate a new auth file with the new password:
   ```bash
   htpasswd -c auth github-actions
   ```

2. Update the Kubernetes secret:
   ```bash
   kubectl create secret generic pushgateway-auth \
     --from-file=auth \
     -n <namespace> \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. Update GitHub repository secrets with the new password

4. Clean up:
   ```bash
   rm auth
   ```

**Note:** Nginx ingress controller automatically reloads when secrets change - no pod restart needed.

### Security Considerations

**Why Basic Auth?**
- Simple to implement and maintain
- Supported natively by Nginx ingress controller
- Adequate for internal CI/CD use case
- No additional dependencies or complexity

**Why Not IP Whitelisting?**
- GitHub Actions uses hundreds of dynamic IP ranges across Azure infrastructure
- IP ranges change frequently as Azure scales
- Maintaining whitelist would be operationally burdensome
- Provides limited security value given the dynamic nature

**Threat Model:**
- **Protected against:** Unauthorized public access, accidental metric pollution
- **Not protected against:** Brute force attacks (consider rate limiting), credential compromise
- **Acceptable for:** Internal CI/CD metrics (non-sensitive operational data)
- **Not suitable for:** Sensitive data or high-value targets

### Monitoring Access

To monitor authentication attempts:

```bash
# Check ingress controller logs for 401 responses
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx --tail=100 | grep pushgateway
```

### Troubleshooting

**401 Unauthorized errors:**
1. Verify secret exists: `kubectl get secret pushgateway-auth -n <namespace>`
2. Check secret contents: `kubectl get secret pushgateway-auth -n <namespace> -o yaml`
3. Verify GitHub secrets are set correctly
4. Test with curl: `curl -u username:password https://pushgateway.rsolv.dev/metrics`

**Secret not found errors:**
1. Ensure secret is created in the same namespace as the ingress
2. Check ingress annotations reference the correct secret name
3. Verify spelling and capitalization

## Alternative Security Options

If basic auth proves insufficient, consider:

1. **API Key Authentication:** Custom middleware with bearer tokens
2. **mTLS (Mutual TLS):** Client certificate authentication
3. **VPN/Private Network:** Remove public ingress entirely
4. **Self-hosted Runners:** Runners within private network with internal-only Pushgateway

Current basic auth implementation is appropriate for the current threat model and operational requirements.
