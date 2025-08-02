# RSOLV Platform Monitoring Configuration

This directory contains all the configuration files needed to set up uptime monitoring for the RSOLV platform using Prometheus, Grafana, and Alertmanager.

## Files Overview

### Core Components
- **blackbox-exporter.yaml** - HTTP endpoint monitoring probe
- **prometheus-config-update.yaml** - Prometheus scrape configuration for RSOLV endpoints
- **rsolv-uptime-alerts.yaml** - Alert rules for downtime, response time, and SSL expiry

### Alerting
- **alertmanager-config-webhook.yaml** - Alertmanager configuration with email and webhook receivers
- **webhook-receiver-deployment.yaml** - Custom webhook receiver to ensure recovery emails are sent

### Visualization
- **rsolv-uptime-dashboard.json** - Grafana dashboard for uptime monitoring

## Quick Deployment

```bash
# 1. Deploy all components
kubectl apply -f blackbox-exporter.yaml
kubectl apply -f prometheus-config-update.yaml
kubectl apply -f rsolv-uptime-alerts.yaml
kubectl apply -f webhook-receiver-deployment.yaml
kubectl apply -f alertmanager-config-webhook.yaml

# 2. Restart services to pick up new configs
kubectl rollout restart deployment/prometheus -n monitoring
kubectl rollout restart deployment/alertmanager -n monitoring

# 3. Import Grafana dashboard manually via UI
```

## What Gets Monitored

- **Main Site**: https://rsolv.dev (2-minute alert threshold)
- **Blog**: https://rsolv.dev/blog (5-minute threshold)
- **Feedback**: https://rsolv.dev/feedback (5-minute threshold)
- **Response Time**: Alert if >3 seconds
- **SSL Certificates**: Alert 7 days before expiry

## Alert Notifications

- **Firing Alerts**: Sent via email through Postmark
- **Recovery Alerts**: Sent via webhook receiver (workaround for Alertmanager issue)

See `/home/dylan/dev/rsolv/RSOLV-infrastructure/MONITORING.md` for complete documentation.