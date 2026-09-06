-- cliptown: isolated namespace inside the shared auth project
create schema if not exists cliptown;
revoke all on schema cliptown from public;
