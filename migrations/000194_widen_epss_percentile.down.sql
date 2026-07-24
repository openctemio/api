-- Revert the percentile column to its original precision. This narrows the
-- integer part back to two digits; it will fail if any stored percentile is
-- >= 100 (expected — the 100.0 rows are exactly why the column was widened).
ALTER TABLE epss_scores ALTER COLUMN percentile TYPE numeric(8,6);
