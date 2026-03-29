-- Migration: add 'partial' scan status and notes column
-- Run this in Supabase SQL Editor if your scans table already exists

-- 1. Drop the old status constraint
ALTER TABLE scans
  DROP CONSTRAINT IF EXISTS scans_status_check;

-- 2. Add 'partial' as a valid status
ALTER TABLE scans
  ADD CONSTRAINT scans_status_check
  CHECK (status IN ('pending', 'running', 'completed', 'partial', 'failed'));

-- 3. Add notes column to store unavailable API reasons (JSON array string)
ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS notes TEXT;

-- 4. Add TLS detail columns for self-hosted SSL inspector
ALTER TABLE scans ADD COLUMN IF NOT EXISTS tls_version TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS cipher_suite TEXT;
