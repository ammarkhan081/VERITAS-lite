-- campaigns
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    sut_descriptor TEXT NOT NULL,    -- JSON
    threat_model TEXT NOT NULL,      -- JSON
    config_snapshot TEXT NOT NULL,   -- JSON: SUT config at campaign start
    phase TEXT NOT NULL DEFAULT 'baseline',
    asr_before REAL,
    asr_after REAL,
    asr_held_out_before REAL,
    asr_held_out_after REAL,
    normal_acc_before REAL,
    normal_acc_after REAL,
    total_steps INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    human_interventions INTEGER DEFAULT 0,
    report TEXT,                     -- JSON: final CampaignReport
    error_message TEXT NOT NULL DEFAULT '',
    updated_at TEXT
);

-- attacks
CREATE TABLE IF NOT EXISTS attacks (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id),
    family TEXT NOT NULL,
    payload TEXT NOT NULL,
    injection_vector TEXT NOT NULL,
    target_tool TEXT NOT NULL,
    task TEXT NOT NULL DEFAULT '',           -- carrier task the payload is embedded in
    pool TEXT NOT NULL DEFAULT 'training',   -- "training" | "held_out"
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    executed_at TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

-- traces
CREATE TABLE IF NOT EXISTS traces (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    attack_id TEXT,                  -- NULL for normal-task traces
    phase TEXT NOT NULL,
    task TEXT NOT NULL,
    tool_calls TEXT NOT NULL,        -- JSON array of ToolCall
    final_response TEXT,
    gates_fired TEXT NOT NULL DEFAULT '[]',  -- JSON array of GateResult
    created_at TEXT NOT NULL,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

-- patches
CREATE TABLE IF NOT EXISTS patches (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    proposal TEXT NOT NULL,          -- JSON: PatchProposal
    status TEXT NOT NULL DEFAULT 'proposed',  -- "proposed" | "applied" | "rejected"
    human_approved INTEGER DEFAULT 0,
    normal_acc_before REAL,
    normal_acc_after REAL,
    applied_at TEXT,
    rejection_reason TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

-- regression_tests
CREATE TABLE IF NOT EXISTS regression_tests (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    attack_id TEXT NOT NULL,
    family TEXT NOT NULL,
    payload TEXT NOT NULL,
    injection_vector TEXT NOT NULL,
    target_tool TEXT NOT NULL,
    evidence TEXT NOT NULL,          -- JSON
    replay_info TEXT NOT NULL,       -- JSON
    sut_version TEXT NOT NULL,
    patch_version TEXT,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',  -- "active" | "resolved"
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

-- held_out_attacks (separate table, sealed at campaign start)
CREATE TABLE IF NOT EXISTS held_out_attacks (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    family TEXT NOT NULL,
    payload TEXT NOT NULL,
    injection_vector TEXT NOT NULL,
    target_tool TEXT NOT NULL,
    task TEXT NOT NULL DEFAULT '',   -- carrier task the payload is embedded in
    sealed_at TEXT NOT NULL,
    executed_at TEXT,
    result TEXT,                     -- NULL until executed after patch
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);

-- indexes
CREATE INDEX IF NOT EXISTS idx_attacks_campaign_id ON attacks(campaign_id);
CREATE INDEX IF NOT EXISTS idx_traces_campaign_id ON traces(campaign_id);
CREATE INDEX IF NOT EXISTS idx_patches_campaign_id ON patches(campaign_id);
CREATE INDEX IF NOT EXISTS idx_regression_tests_status ON regression_tests(status);
CREATE INDEX IF NOT EXISTS idx_regression_tests_campaign_id ON regression_tests(campaign_id);
CREATE INDEX IF NOT EXISTS idx_held_out_attacks_campaign_id ON held_out_attacks(campaign_id);

