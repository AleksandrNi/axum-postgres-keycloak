CREATE SCHEMA IF NOT EXISTS public;
GRANT USAGE ON SCHEMA PUBLIC TO PUBLIC;
GRANT CREATE ON SCHEMA PUBLIC TO PUBLIC;

-- CREATE SCHEMA IF NOT EXISTS service_db_kc;
-- GRANT USAGE ON SCHEMA service_db_kc TO PUBLIC;
-- GRANT CREATE ON SCHEMA service_db_kc TO PUBLIC;
-- create table service_db_kc.databasechangeloglock
-- (
--     id          INTEGER NOT NULL,
--     locked      BOOLEAN NOT NULL,
--     lockgranted TIMESTAMP,
--     lockedby    VARCHAR(255)
-- );
--
-- ALTER TABLE service_db_kc.databasechangeloglock
--     owner TO postgres;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";