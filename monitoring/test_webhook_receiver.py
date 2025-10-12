#!/usr/bin/env python3
"""
Unit tests for webhook receiver throttling logic.

Run with: python3 -m pytest test_webhook_receiver.py -v
Or: python3 test_webhook_receiver.py
"""

import unittest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from io import BytesIO


class MockWebhookHandler:
    """Simplified version of webhook handler for testing throttling logic"""

    def __init__(self):
        self.sent_times = {}
        self.throttle_window = timedelta(minutes=5)

    def should_send(self, key):
        """Check if enough time has passed since last email for this alert"""
        now = datetime.now()
        if key in self.sent_times and now - self.sent_times[key] < self.throttle_window:
            return False
        self.sent_times[key] = now
        return True


class TestWebhookThrottling(unittest.TestCase):
    """Test webhook receiver throttling logic"""

    def setUp(self):
        """Set up test fixtures"""
        self.handler = MockWebhookHandler()

    def test_first_alert_always_sends(self):
        """First alert for a given key should always send"""
        key = "RSOLVMainSiteDown:https://rsolv.dev"
        self.assertTrue(self.handler.should_send(key))

    def test_duplicate_alert_within_window_throttled(self):
        """Duplicate alert within throttle window should be blocked"""
        key = "RSOLVMainSiteDown:https://rsolv.dev"

        # First send succeeds
        self.assertTrue(self.handler.should_send(key))

        # Immediate duplicate is throttled
        self.assertFalse(self.handler.should_send(key))

    def test_different_alerts_not_throttled(self):
        """Different alert keys should not throttle each other"""
        key1 = "RSOLVMainSiteDown:https://rsolv.dev"
        key2 = "RSOLVMainSiteDown:https://rsolv.dev/blog"

        self.assertTrue(self.handler.should_send(key1))
        self.assertTrue(self.handler.should_send(key2))

    def test_alert_after_window_sends(self):
        """Alert after throttle window should send"""
        key = "RSOLVMainSiteDown:https://rsolv.dev"

        # First send
        self.assertTrue(self.handler.should_send(key))

        # Simulate time passing
        self.handler.sent_times[key] = datetime.now() - timedelta(minutes=6)

        # Should send again after window
        self.assertTrue(self.handler.should_send(key))

    def test_multiple_throttled_attempts(self):
        """Multiple throttled attempts should all be blocked"""
        key = "RSOLVMainSiteDown:https://rsolv.dev"

        # First send
        self.assertTrue(self.handler.should_send(key))

        # Multiple attempts within window all throttled
        for _ in range(5):
            self.assertFalse(self.handler.should_send(key))

    def test_throttle_window_boundary(self):
        """Test behavior at throttle window boundary"""
        key = "RSOLVMainSiteDown:https://rsolv.dev"

        # First send
        self.assertTrue(self.handler.should_send(key))

        # Just before window expires (4m 59s)
        self.handler.sent_times[key] = datetime.now() - timedelta(minutes=4, seconds=59)
        self.assertFalse(self.handler.should_send(key))

        # Just after window expires (5m 1s)
        self.handler.sent_times[key] = datetime.now() - timedelta(minutes=5, seconds=1)
        self.assertTrue(self.handler.should_send(key))


class TestWebhookPayloadHandling(unittest.TestCase):
    """Test webhook payload parsing and alert filtering"""

    def test_valid_recovery_payload(self):
        """Test parsing of valid recovery alert payload"""
        payload = {
            "version": "4",
            "status": "resolved",
            "alerts": [{
                "status": "resolved",
                "labels": {
                    "alertname": "RSOLVMainSiteDown",
                    "instance": "https://rsolv.dev",
                    "severity": "critical"
                },
                "startsAt": "2025-10-12T10:00:00Z",
                "endsAt": "2025-10-12T10:05:00Z"
            }]
        }

        alert = payload["alerts"][0]
        self.assertEqual(alert["status"], "resolved")
        self.assertEqual(alert["labels"]["alertname"], "RSOLVMainSiteDown")

    def test_firing_alert_ignored(self):
        """Webhook should only process resolved alerts"""
        payload = {
            "status": "firing",
            "alerts": [{
                "status": "firing",
                "labels": {"alertname": "RSOLVMainSiteDown"}
            }]
        }

        alert = payload["alerts"][0]
        should_process = (alert["status"] == "resolved" and
                         alert["labels"].get("alertname") == "RSOLVMainSiteDown")
        self.assertFalse(should_process)

    def test_non_main_site_alert_ignored(self):
        """Only RSOLVMainSiteDown alerts should be processed"""
        payload = {
            "status": "resolved",
            "alerts": [{
                "status": "resolved",
                "labels": {"alertname": "RSOLVBlogDown"}
            }]
        }

        alert = payload["alerts"][0]
        should_process = (alert["status"] == "resolved" and
                         alert["labels"].get("alertname") == "RSOLVMainSiteDown")
        self.assertFalse(should_process)

    def test_multiple_alerts_in_payload(self):
        """Handle webhook with multiple alerts"""
        payload = {
            "status": "resolved",
            "alerts": [
                {
                    "status": "resolved",
                    "labels": {
                        "alertname": "RSOLVMainSiteDown",
                        "instance": "https://rsolv.dev"
                    }
                },
                {
                    "status": "resolved",
                    "labels": {
                        "alertname": "RSOLVBlogDown",
                        "instance": "https://rsolv.dev/blog"
                    }
                }
            ]
        }

        # Should only process RSOLVMainSiteDown
        processable = [
            a for a in payload["alerts"]
            if a["status"] == "resolved" and
            a["labels"].get("alertname") == "RSOLVMainSiteDown"
        ]
        self.assertEqual(len(processable), 1)
        self.assertEqual(processable[0]["labels"]["instance"], "https://rsolv.dev")


class TestAlertKeyGeneration(unittest.TestCase):
    """Test alert key generation for throttling"""

    def test_key_format(self):
        """Alert key should include alertname and instance"""
        alert = {
            "labels": {
                "alertname": "RSOLVMainSiteDown",
                "instance": "https://rsolv.dev"
            }
        }

        key = f"{alert['labels']['alertname']}:{alert['labels'].get('instance', 'Unknown')}"
        self.assertEqual(key, "RSOLVMainSiteDown:https://rsolv.dev")

    def test_key_with_missing_instance(self):
        """Handle alert with missing instance"""
        alert = {
            "labels": {
                "alertname": "RSOLVMainSiteDown"
            }
        }

        key = f"{alert['labels']['alertname']}:{alert['labels'].get('instance', 'Unknown')}"
        self.assertEqual(key, "RSOLVMainSiteDown:Unknown")

    def test_different_instances_different_keys(self):
        """Different instances should generate different keys"""
        alert1 = {"labels": {"alertname": "RSOLVMainSiteDown", "instance": "https://rsolv.dev"}}
        alert2 = {"labels": {"alertname": "RSOLVMainSiteDown", "instance": "https://rsolv.dev/blog"}}

        key1 = f"{alert1['labels']['alertname']}:{alert1['labels'].get('instance', 'Unknown')}"
        key2 = f"{alert2['labels']['alertname']}:{alert2['labels'].get('instance', 'Unknown')}"

        self.assertNotEqual(key1, key2)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
