-- ==========================================
-- PLANE A: CVE KNOWLEDGE TABLES (Global Read-Only)
-- ==========================================

-- Primary CVE Table
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    source_of_truth TEXT,
    title TEXT,
    description TEXT,
    published_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    vuln_status TEXT,
    assigner_org TEXT,
    cna_org TEXT,
    raw_cve_json JSONB,
    raw_nvd_json JSONB,
    first_seen_at TIMESTAMPTZ DEFAULT now(),
    last_synced_at TIMESTAMPTZ DEFAULT now(),
    internal_label TEXT,
    label_generated_at TIMESTAMPTZ
);

-- Aliases Table (mapping between different advisory ecosystems)
CREATE TABLE IF NOT EXISTS cve_aliases (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
    alias_type TEXT NOT NULL, -- CVE, GHSA, OSV, PYSEC, RUSTSEC, GO, OTHER
    alias_value TEXT NOT NULL,
    UNIQUE (cve_id, alias_type, alias_value)
);

-- Metrics Table (CVSS and CWE scores)
CREATE TABLE IF NOT EXISTS cve_metrics (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL, -- e.g. nvd, cvelist, osv
    cvss_version TEXT, -- 2.0, 3.0, 3.1, 4.0
    vector_string TEXT,
    base_score NUMERIC(3,1),
    base_severity TEXT,
    exploitability_score NUMERIC(4,1),
    impact_score NUMERIC(4,1),
    cwe_id TEXT,
    UNIQUE (cve_id, source, cvss_version)
);

-- References Table
CREATE TABLE IF NOT EXISTS cve_references (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    url TEXT NOT NULL,
    ref_type TEXT,
    tags JSONB,
    UNIQUE (cve_id, url)
);

-- Affected Products (CPE and Package ranges)
CREATE TABLE IF NOT EXISTS cve_affected_products (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL, -- nvd, cvelist, osv
    vendor TEXT,
    product TEXT,
    ecosystem TEXT, -- PyPI, npm, Maven, Go, etc.
    package_name TEXT,
    platform TEXT,
    cpe_uri TEXT,
    os_type TEXT, -- linux, windows, macos, any, container
    os_distro TEXT, -- rhel, ubuntu, debian, arch, windows_10, etc.
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    fixed_version TEXT,
    raw_range JSONB
);

-- KEV (Known Exploited Vulnerabilities) Table
CREATE TABLE IF NOT EXISTS cve_kev (
    cve_id TEXT PRIMARY KEY REFERENCES cves(cve_id) ON DELETE CASCADE,
    known_exploited BOOLEAN DEFAULT TRUE,
    cisa_date_added DATE,
    cisa_due_date DATE,
    cisa_vulnerability_name TEXT,
    cisa_required_action TEXT,
    cisa_notes TEXT,
    raw_kev_json JSONB
);

-- Source Documents (Raw archiving for replay/reparse)
CREATE TABLE IF NOT EXISTS cve_source_documents (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT REFERENCES cves(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL, -- nvd, cvelist, osv, kev
    source_record_id TEXT,
    raw_json JSONB NOT NULL,
    fetched_at TIMESTAMPTZ DEFAULT now()
);

-- Sync State Table
CREATE TABLE IF NOT EXISTS sync_state (
    source TEXT PRIMARY KEY,
    last_successful_sync TIMESTAMPTZ NOT NULL
);

-- ==========================================
-- PLANE B: FINDINGS TABLES (Scanners Write-To)
-- ==========================================

-- Assets Table (hosts, ports, urls, packages, domains)
CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    asset_type TEXT NOT NULL, -- domain, subdomain, ip, port, url, container, package
    value TEXT NOT NULL,
    parent_id BIGINT REFERENCES assets(id) ON DELETE SET NULL,
    first_seen_at TIMESTAMPTZ DEFAULT now(),
    last_seen_at TIMESTAMPTZ DEFAULT now(),
    metadata JSONB,
    source_tool TEXT,
    UNIQUE (asset_type, value)
);

-- Scan Sessions Table
CREATE TABLE IF NOT EXISTS scan_sessions (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT UNIQUE NOT NULL,
    tool TEXT NOT NULL, -- asm, sbom, container, baseline, pentest
    target TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    status TEXT NOT NULL, -- running, completed, failed, cancelled
    metadata JSONB
);

-- Central Findings Table
CREATE TABLE IF NOT EXISTS findings (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT REFERENCES scan_sessions(session_id) ON DELETE CASCADE,
    asset_id BIGINT REFERENCES assets(id) ON DELETE CASCADE,
    cve_id TEXT REFERENCES cves(cve_id) ON DELETE SET NULL,
    internal_label TEXT,
    finding_type TEXT NOT NULL, -- cve, misconfiguration, exposed_secret, open_port, takeover_candidate, outdated_component, hardening_gap
    severity TEXT NOT NULL, -- critical, high, medium, low, info
    tool TEXT NOT NULL, -- nuclei, nmap, sbom-grype, trivy, manual, etc.
    template_id TEXT,
    status TEXT NOT NULL DEFAULT 'open', -- open, confirmed, false_positive, mitigated, accepted_risk
    false_positive BOOLEAN DEFAULT FALSE,
    false_positive_note TEXT,
    first_found_at TIMESTAMPTZ DEFAULT now(),
    last_confirmed_at TIMESTAMPTZ,
    raw_output JSONB,
    notes TEXT
);

-- Audit log of status changes on findings
CREATE TABLE IF NOT EXISTS finding_history (
    id BIGSERIAL PRIMARY KEY,
    finding_id BIGINT REFERENCES findings(id) ON DELETE CASCADE,
    old_status TEXT,
    new_status TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    changed_at TIMESTAMPTZ DEFAULT now(),
    note TEXT
);

-- ==========================================
-- INDEXES FOR PERFORMANCE
-- ==========================================

-- Knowledge Plane Indexes
CREATE INDEX IF NOT EXISTS idx_cves_updated_at         ON cves(updated_at);
CREATE INDEX IF NOT EXISTS idx_cves_published_at       ON cves(published_at);
CREATE INDEX IF NOT EXISTS idx_cves_internal_label     ON cves(internal_label);
CREATE INDEX IF NOT EXISTS idx_cves_vuln_status        ON cves(vuln_status);
CREATE INDEX IF NOT EXISTS idx_cves_raw_nvd_gin        ON cves USING GIN (raw_nvd_json);
CREATE INDEX IF NOT EXISTS idx_cves_raw_cve_gin        ON cves USING GIN (raw_cve_json);
CREATE INDEX IF NOT EXISTS idx_cves_fts                ON cves USING GIN (to_tsvector('english', coalesce(title,'') || ' ' || coalesce(description,'')));
CREATE INDEX IF NOT EXISTS idx_metrics_score           ON cve_metrics(base_score);
CREATE INDEX IF NOT EXISTS idx_metrics_cve_source      ON cve_metrics(cve_id, source);
CREATE INDEX IF NOT EXISTS idx_kev_date_added          ON cve_kev(cisa_date_added);
CREATE INDEX IF NOT EXISTS idx_products_cpe            ON cve_affected_products(cpe_uri);
CREATE INDEX IF NOT EXISTS idx_products_package        ON cve_affected_products(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_products_vendor_product ON cve_affected_products(vendor, product);
CREATE INDEX IF NOT EXISTS idx_products_os             ON cve_affected_products(os_type, os_distro);
CREATE INDEX IF NOT EXISTS idx_aliases_value           ON cve_aliases(alias_value);
CREATE INDEX IF NOT EXISTS idx_refs_url                ON cve_references(url);
CREATE INDEX IF NOT EXISTS idx_label_prefix            ON cves(internal_label text_pattern_ops);

-- Findings Plane Indexes
CREATE INDEX IF NOT EXISTS idx_findings_cve_id         ON findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_findings_asset_id       ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_session        ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_status         ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity       ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_label          ON findings(internal_label);
CREATE INDEX IF NOT EXISTS idx_assets_value            ON assets(value);
CREATE INDEX IF NOT EXISTS idx_assets_type             ON assets(asset_type);

-- Unique index to prevent duplicate findings for the same asset within a single session
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique_session 
ON findings (session_id, asset_id, template_id, COALESCE(cve_id, ''));

-- ==========================================
-- VIEWS
-- ==========================================

-- Helper View: Get the highest CVSS base score for each CVE
CREATE OR REPLACE VIEW v_highest_cvss_score AS
SELECT 
    cve_id, 
    MAX(base_score) AS max_base_score
FROM cve_metrics
GROUP BY cve_id;

-- Actionable CVEs View: Known exploited (KEV) OR CVSS >= 7.0, ordered by KEV then highest score
CREATE OR REPLACE VIEW v_actionable_cves AS
SELECT 
    c.cve_id,
    c.title,
    c.description,
    c.internal_label,
    COALESCE(k.known_exploited, FALSE) AS known_exploited,
    ms.max_base_score AS cvss_score,
    c.published_at,
    c.updated_at
FROM cves c
LEFT JOIN v_highest_cvss_score ms ON c.cve_id = ms.cve_id
LEFT JOIN cve_kev k ON c.cve_id = k.cve_id
WHERE COALESCE(k.known_exploited, FALSE) = TRUE OR ms.max_base_score >= 7.0
ORDER BY known_exploited DESC, cvss_score DESC NULLS LAST;

-- Critical CVEs View: CVSS >= 9.0 or KEV
CREATE OR REPLACE VIEW v_critical_cves AS
SELECT 
    c.cve_id,
    c.title,
    c.description,
    c.internal_label,
    COALESCE(k.known_exploited, FALSE) AS known_exploited,
    ms.max_base_score AS cvss_score,
    c.published_at,
    c.updated_at
FROM cves c
LEFT JOIN v_highest_cvss_score ms ON c.cve_id = ms.cve_id
LEFT JOIN cve_kev k ON c.cve_id = k.cve_id
WHERE ms.max_base_score >= 9.0 OR COALESCE(k.known_exploited, FALSE) = TRUE;

-- Open Findings View: Joins findings with assets and CVE information
CREATE OR REPLACE VIEW v_open_findings AS
SELECT 
    f.id AS finding_id,
    f.session_id,
    f.asset_id,
    a.asset_type,
    a.value AS asset_value,
    f.cve_id,
    f.internal_label,
    f.finding_type,
    f.severity,
    f.tool,
    f.template_id,
    f.status,
    f.first_found_at,
    f.last_confirmed_at,
    c.title AS cve_title,
    c.description AS cve_description
FROM findings f
JOIN assets a ON f.asset_id = a.id
LEFT JOIN cves c ON f.cve_id = c.cve_id
WHERE f.status = 'open';

-- Findings By Severity View: Count of open findings grouped by severity
CREATE OR REPLACE VIEW v_findings_by_severity AS
SELECT 
    severity,
    COUNT(*) AS open_count
FROM findings
WHERE status = 'open'
GROUP BY severity;
