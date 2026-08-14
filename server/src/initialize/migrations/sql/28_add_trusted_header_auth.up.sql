alter type account_type add value 'TRUSTED_HEADER';

create table trusted_header_users
(
    "user"  uuid         not null references users ON DELETE CASCADE,
    subject varchar(256) not null unique,
    name    varchar(256) not null
);
