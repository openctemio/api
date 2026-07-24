-- EPSS percentile is stored on a 0-100 scale (the sync multiplies the feed's
-- 0-1 value by 100), but the column was numeric(8,6) whose maximum is
-- 99.999999. The top CVEs have a feed percentile of exactly 1.0, which becomes
-- 100.0 and overflowed ("numeric field overflow") — failing the whole EPSS
-- COPY. Widen the integer part so 100.000000 fits. Non-destructive: widening a
-- numeric's precision preserves every existing value.
ALTER TABLE epss_scores ALTER COLUMN percentile TYPE numeric(9,6);
