-- Wave 4: RFC 9396 (RAR) + OIDC Core §5.5 (Claims Request)
-- These columns are nullable so existing rows continue to read as NULL.
ALTER TABLE authorization_codes ADD COLUMN authorization_details TEXT;
ALTER TABLE authorization_codes ADD COLUMN claims_request TEXT;
