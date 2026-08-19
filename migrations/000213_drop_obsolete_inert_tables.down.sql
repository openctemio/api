-- Down for 000213: recreate the 5 dropped tables (STRUCTURE ONLY).
--
-- No data is restored and none is lost: all 5 tables were 0-row when dropped.
-- Each table is recreated exactly as its creating migration defined it, and for the
-- four tables whose id DEFAULT was later switched to uuid_generate_v7() by
-- 000062_uuid_v7, that ALTER is reapplied here so the restored shape matches the
-- live pre-drop schema exactly (threat_actor_cves was never touched by 000062).

-- 1. agent_metrics — original DDL from 000016_agents.up.sql.
CREATE TABLE IF NOT EXISTS agent_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    metric_type VARCHAR(50) NOT NULL,
    metric_value DECIMAL(12,4) NOT NULL,
    labels JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE agent_metrics IS 'Agent performance metrics';
CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_id ON agent_metrics(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_type ON agent_metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_recorded_at ON agent_metrics(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_type_time ON agent_metrics(agent_id, metric_type, recorded_at DESC);
ALTER TABLE agent_metrics ALTER COLUMN id SET DEFAULT uuid_generate_v7();  -- from 000062

-- 2. email_logs — original DDL from 000021_audit_logs.up.sql.
CREATE TABLE IF NOT EXISTS email_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email_type VARCHAR(100) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    subject VARCHAR(500),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    task_id VARCHAR(255),
    queue_name VARCHAR(100),
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    last_error TEXT,
    related_entity_type VARCHAR(100),
    related_entity_id UUID,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    queued_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,

    CONSTRAINT chk_email_logs_status CHECK (status IN ('pending', 'queued', 'processing', 'sent', 'failed', 'bounced'))
);
COMMENT ON TABLE email_logs IS 'Email delivery tracking';
CREATE INDEX IF NOT EXISTS idx_email_logs_recipient ON email_logs(recipient_email);
CREATE INDEX IF NOT EXISTS idx_email_logs_status ON email_logs(status);
CREATE INDEX IF NOT EXISTS idx_email_logs_email_type ON email_logs(email_type);
CREATE INDEX IF NOT EXISTS idx_email_logs_tenant_id ON email_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_created_at ON email_logs(created_at DESC);
ALTER TABLE email_logs ALTER COLUMN id SET DEFAULT uuid_generate_v7();  -- from 000062

-- 3. registration_tokens — original DDL from 000016_agents.up.sql.
CREATE TABLE IF NOT EXISTS registration_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    token_prefix VARCHAR(12) NOT NULL,
    agent_type VARCHAR(50) DEFAULT 'agent',
    agent_name_prefix VARCHAR(100),
    default_scopes TEXT[] DEFAULT '{}',
    default_capabilities TEXT[] DEFAULT '{}',
    default_tools TEXT[] DEFAULT '{}',
    default_labels JSONB DEFAULT '{}',
    max_uses INTEGER DEFAULT 1,
    uses_count INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE registration_tokens IS 'Tokens for automatic agent registration';
CREATE INDEX IF NOT EXISTS idx_registration_tokens_tenant ON registration_tokens(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_registration_tokens_hash ON registration_tokens(token_hash) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_registration_tokens_prefix ON registration_tokens(token_prefix);
CREATE INDEX IF NOT EXISTS idx_registration_tokens_expires ON registration_tokens(expires_at) WHERE expires_at IS NOT NULL;
ALTER TABLE registration_tokens ALTER COLUMN id SET DEFAULT uuid_generate_v7();  -- from 000062

-- 4. scan_profile_template_sources — original DDL from 000029_finding_data_flows.up.sql.
CREATE TABLE IF NOT EXISTS scan_profile_template_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_profile_id UUID NOT NULL REFERENCES scan_profiles(id) ON DELETE CASCADE,
    source_id UUID NOT NULL REFERENCES template_sources(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_profile_source UNIQUE (scan_profile_id, source_id)
);
COMMENT ON TABLE scan_profile_template_sources IS 'Links scan profiles to template sources';
CREATE INDEX IF NOT EXISTS idx_spts_profile ON scan_profile_template_sources(scan_profile_id);
CREATE INDEX IF NOT EXISTS idx_spts_source ON scan_profile_template_sources(source_id);
ALTER TABLE scan_profile_template_sources ALTER COLUMN id SET DEFAULT uuid_generate_v7();  -- from 000062

-- 5. threat_actor_cves — original DDL from 000121_threat_actors.up.sql.
--    (id has no DEFAULT in the original; 000062 never touched this table.)
CREATE TABLE IF NOT EXISTS threat_actor_cves (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    threat_actor_id UUID NOT NULL REFERENCES threat_actors(id) ON DELETE CASCADE,
    cve_id VARCHAR(30) NOT NULL,
    confidence VARCHAR(20) DEFAULT 'medium',
    source VARCHAR(100),
    first_observed DATE,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, threat_actor_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_threat_actor_cves_tenant ON threat_actor_cves(tenant_id);
CREATE INDEX IF NOT EXISTS idx_threat_actor_cves_actor ON threat_actor_cves(threat_actor_id);
CREATE INDEX IF NOT EXISTS idx_threat_actor_cves_cve ON threat_actor_cves(cve_id);
