-- RFC 9449 section 10: DPoP-bound authorization codes. The client presents the
-- JWK thumbprint of its DPoP key (dpop_jkt) at the authorization endpoint or
-- PAR, the AS records it here and requires a DPoP proof with the SAME key at
-- code redemption. NULL means the code is not DPoP-bound.
ALTER TABLE authorization_codes ADD COLUMN dpop_jkt TEXT;
