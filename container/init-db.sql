-- Только начальный postgres-superuser может прочитать смонтированный secret.
SELECT format('CREATE ROLE nextcloud LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
              pg_read_file('/run/secrets/db_password')) \gexec
CREATE DATABASE nextcloud OWNER nextcloud;
REVOKE ALL ON DATABASE nextcloud FROM PUBLIC;
