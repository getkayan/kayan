-- Reverses 0001_initial_schema.up.sql.
--
-- This drops every table and the identity data in them. It exists so a
-- migration can be rolled back during development; running it against a
-- production database destroys every account.

DROP TABLE IF EXISTS role_definitions;
DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS mfa_enrollments;
DROP TABLE IF EXISTS relation_tuples;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS auth_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS identities;
