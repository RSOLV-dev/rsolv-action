# RFC-026: CrowdSec Endpoint Protection Implementation

**RFC Number**: 026  
**Title**: CrowdSec Endpoint Protection for RSOLV Infrastructure  
**Author**: Infrastructure Team  
**Status**: Draft  
**Created**: 2025-01-22  
**Linear Issue**: TBD  

## Summary

This RFC proposes implementing CrowdSec as a comprehensive endpoint protection solution for the RSOLV infrastructure. CrowdSec will provide behavior-based intrusion detection and prevention, protecting our services from malicious actors through both local analysis and community-driven threat intelligence. The implementation will be at the Kubernetes cluster level, protecting all RSOLV services (landing page, API, and future services) with minimal per-service configuration.

## Motivation

The RSOLV platform currently relies on basic Nginx ingress protection and application-level security patterns. As we scale and expose more endpoints, we need:

1. **Proactive Protection**: Detect and block malicious behavior before it reaches our applications
2. **Community Intelligence**: Leverage crowd-sourced threat data to protect against known bad actors
3. **Behavioral Analysis**: Identify attack patterns beyond simple rate limiting
4. **Unified Security**: Consistent protection across all services without duplicating security logic
5. **Zero-Day Protection**: Defend against emerging threats through behavioral detection

Current gaps in our security posture:
- No protection against distributed attacks
- Limited visibility into attack patterns
- No automated response to emerging threats
- Manual blacklisting is reactive, not proactive

## Proposed Solution

### Architecture Overview

Deploy CrowdSec at the Kubernetes cluster level with the following components:

```
┌─────────────────────┐
│   Internet Traffic  │
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│   Nginx Ingress     │
│  + CrowdSec Bouncer │
└──────────┬──────────┘
           │
┌──────────▼──────────┐     ┌─────────────────┐
│  CrowdSec Security  │────▶│ CrowdSec Cloud  │
│      Engine          │     │   (CTI Feed)    │
└──────────┬──────────┘     └─────────────────┘
           │
┌──────────▼──────────┐
│   RSOLV Services    │
│ • Landing (Phoenix) │
│ • API (Phoenix)     │
│ • Action (GitHub)   │
└─────────────────────┘
```

### Implementation Details

#### 1. CrowdSec Security Engine Deployment

Deploy CrowdSec as a DaemonSet to analyze logs from all nodes:

```yaml
# crowdsec-values.yaml
container_runtime: containerd
agent:
  acquisition:
    # Monitor Nginx ingress logs
    - namespace: ingress-nginx
      podName: ingress-nginx-controller-*
      program: nginx
    # Monitor RSOLV services
    - namespace: rsolv-production
      podName: rsolv-landing-*
      program: phoenix
    - namespace: rsolv-production
      podName: rsolv-api-*
      program: phoenix
  env:
    - name: COLLECTIONS
      value: "crowdsecurity/nginx crowdsecurity/http-cve crowdsecurity/whitelist-good-actors"
    - name: DISABLE_ONLINE_API
      value: "false"  # Enable crowd-sourced intelligence
lapi:
  env:
    - name: ENROLL_KEY
      value: "${CROWDSEC_ENROLL_KEY}"
    - name: ENROLL_INSTANCE_NAME
      value: "rsolv-k8s-production"
    - name: ENROLL_TAGS
      value: "k8s production security-platform"
```

#### 2. Nginx Ingress Integration

Integrate CrowdSec with our existing Nginx ingress controller:

```yaml
# nginx-ingress-crowdsec-patch.yaml
controller:
  extraVolumes:
  - name: crowdsec-bouncer-plugin
    emptyDir: {}
  extraInitContainers:
  - name: init-crowdsec-bouncer
    image: crowdsecurity/lua-bouncer-plugin
    env:
      - name: API_URL
        value: "http://crowdsec-service.crowdsec.svc.cluster.local:8080"
      - name: API_KEY
        valueFrom:
          secretKeyRef:
            name: crowdsec-bouncer-key
            key: key
      - name: BOUNCER_CONFIG
        value: "/crowdsec/crowdsec-bouncer.conf"
    volumeMounts:
    - name: crowdsec-bouncer-plugin
      mountPath: /lua_plugins
  extraVolumeMounts:
  - name: crowdsec-bouncer-plugin
    mountPath: /etc/nginx/lua/plugins/crowdsec
    subPath: crowdsec
  config:
    plugins: "crowdsec"
    lua-shared-dicts: "crowdsec_cache: 50m"
```

#### 3. Collections and Scenarios

Deploy with curated security collections:

- **Base Collections**:
  - `crowdsecurity/nginx`: Nginx-specific attack patterns
  - `crowdsecurity/http-cve`: Known HTTP CVE exploits
  - `crowdsecurity/whitelist-good-actors`: Prevent false positives

- **Custom Scenarios** for RSOLV:
  - API key brute-forcing detection
  - Pattern endpoint abuse detection
  - Webhook spam protection
  - GraphQL introspection attacks (future)

#### 4. Monitoring Integration

Extend our existing Grafana setup with CrowdSec dashboards:

```yaml
# grafana-crowdsec-dashboard.yaml
- name: CrowdSec Security Dashboard
  metrics:
    - Attacks blocked by type
    - Top attacking IPs/countries
    - Decision effectiveness
    - Community contribution stats
```

### Phased Rollout

#### Phase 1: Staging Environment (Week 1)
- Deploy CrowdSec in detection-only mode
- Monitor false positive rate
- Tune detection scenarios
- Validate performance impact

#### Phase 2: Production Detection Mode (Week 2)
- Deploy to production in detection mode
- Configure alerts but don't block
- Analyze attack patterns
- Build whitelist of legitimate services

#### Phase 3: Production Protection Mode (Week 3)
- Enable blocking mode
- Monitor customer impact
- Fine-tune scenarios
- Document incident response

#### Phase 4: Advanced Features (Week 4+)
- Custom scenarios for RSOLV-specific patterns
- Integration with our security pattern detection
- Automated reporting to security team
- Community intelligence contribution

## Benefits

1. **Immediate Protection**: Block known bad actors from CrowdSec's community database
2. **Learning System**: Improves over time as it learns attack patterns
3. **Low Overhead**: ~50MB RAM per agent, minimal CPU usage
4. **API Protection**: Specific protection for our credential vending and pattern APIs
5. **Compliance**: Helps meet security requirements for enterprise customers
6. **Visibility**: Comprehensive attack analytics and trends

## Implementation Plan

### Week 1: Preparation
- [ ] Create CrowdSec namespace in Kubernetes
- [ ] Generate enrollment keys from CrowdSec Console
- [ ] Prepare Helm values for staging deployment
- [ ] Create monitoring dashboards

### Week 2: Staging Deployment
- [ ] Deploy CrowdSec Security Engine
- [ ] Configure Nginx bouncer integration
- [ ] Validate log collection
- [ ] Test detection scenarios

### Week 3: Production Rollout
- [ ] Deploy in detection mode
- [ ] Monitor for false positives
- [ ] Create custom whitelists
- [ ] Enable protection mode

### Week 4: Optimization
- [ ] Create RSOLV-specific scenarios
- [ ] Integrate with alerting
- [ ] Document runbooks
- [ ] Train team on operations

## Alternatives Considered

1. **AWS WAF**: 
   - Pros: Native AWS integration
   - Cons: Vendor lock-in, higher cost, less flexibility

2. **ModSecurity**: 
   - Pros: Industry standard, rule-based
   - Cons: Complex configuration, no crowd intelligence

3. **Fail2ban**: 
   - Pros: Simple, well-known
   - Cons: Limited to log analysis, no modern features

4. **Commercial WAF (Cloudflare, Imperva)**:
   - Pros: Comprehensive features
   - Cons: High cost, data sovereignty concerns

## Security Considerations

1. **Data Privacy**: CrowdSec only shares attacking IPs, not customer data
2. **False Positives**: Implement gradual rollout with monitoring
3. **Bypass Risk**: Implement at cluster level to prevent bypass
4. **Performance**: Use caching to minimize latency impact

## Cost Analysis

- **CrowdSec Engine**: Free (open source)
- **Community Threat Intelligence**: Free
- **Premium Blocklists** (optional): ~$20-50/month
- **Infrastructure**: Minimal (< 1 CPU core, 200MB RAM total)

## Open Questions

1. Should we contribute our detected patterns back to the community?
2. Do we need premium blocklists for enhanced protection?
3. Should we implement CrowdSec at the application level for deeper integration?
4. How do we handle customer-reported false positives?

## Success Metrics

- **Attack Reduction**: 80%+ reduction in successful attacks
- **False Positive Rate**: < 0.1% of legitimate traffic blocked
- **Performance Impact**: < 5ms added latency
- **Operational Burden**: < 2 hours/week maintenance

## References

- [CrowdSec Documentation](https://docs.crowdsec.net/)
- [CrowdSec Kubernetes Guide](https://docs.crowdsec.net/u/getting_started/installation/kubernetes)
- [Nginx Bouncer Integration](https://docs.crowdsec.net/u/bouncers/nginx/)
- [CrowdSec vs Fail2ban Comparison](https://www.crowdsec.net/blog/crowdsec-not-your-typical-fail2ban-clone)