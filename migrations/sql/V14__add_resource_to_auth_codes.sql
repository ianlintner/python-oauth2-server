-- RFC 8707: Resource Indicators — store the requested resource URI on authorization codes
-- so it can be threaded through to the access token's audience claim.
ALTER TABLE authorization_codes ADD COLUMN resource TEXT;
