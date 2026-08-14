drop table if exists trusted_header_users;

-- Note: PostgreSQL does not support removing individual enum values.
-- The TRUSTED_HEADER value added to account_type remains in place after this
-- down migration, but is unused once the table is dropped.
