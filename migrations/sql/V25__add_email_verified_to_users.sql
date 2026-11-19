-- Track whether a user's email address was established as verified.
-- Only a verified email may match the admin email allow-list.
-- Backfill rule: rows for Microsoft and Azure social accounts (usernames
-- starting with microsoft: or azure:) hold an unverified address and become
-- FALSE. All other rows (password users, google:, github:) become TRUE.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE;
UPDATE users SET email_verified = FALSE WHERE username LIKE 'microsoft:%' OR username LIKE 'azure:%';
