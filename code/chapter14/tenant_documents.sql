-- Run as the schema owner in a disposable PostgreSQL database.
-- The application role must be a separate non-owner without BYPASSRLS.
CREATE TABLE documents (
    tenant_id text NOT NULL,
    document_id text NOT NULL,
    title text NOT NULL,
    body text NOT NULL,
    PRIMARY KEY (tenant_id, document_id)
);

ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_documents ON documents
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
