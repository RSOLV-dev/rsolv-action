-- Fix for analytics_events missing metadata column
ALTER TABLE analytics_events
ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';