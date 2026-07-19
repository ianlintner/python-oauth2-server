-- OIDC Back-Channel Logout, Front-Channel Logout, and RP-Initiated Logout fields
ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN frontchannel_logout_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN frontchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '';
