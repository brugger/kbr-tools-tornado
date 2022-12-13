
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS user_profile (
   id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
   idp_user_id UUID NOT NULL,
   email varchar(200),
   username varchar( 200 ),
   superuser boolean NOT NULL default False,
   create_date timestamp default now(),
   last_login timestamp
);

CREATE TABLE IF NOT EXISTS acl (
    id UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
    endpoint varchar(50) NOT NULL ,
    can_create boolean default FALSE,
    can_read   boolean default False,
    can_update boolean default False,
    can_delete boolean default False
);

CREATE TABLE IF NOT EXISTS role (
    id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
    name varchar( 200 ) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS user_role (
   id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
   user_profile_id UUID NOT NULL references user_profile( id ),
   role_id UUID NOT NULL references role( id )
);

CREATE TABLE IF NOT EXISTS acl_role (
    id  UUID NOT NULL DEFAULT  uuid_generate_v4 () PRIMARY KEY,
    acl_id UUID NOT NULL references acl( id ),
    role_id UUID NOT NULL references role( id )
);


INSERT INTO user_profile (idp_user_id, email, username, superuser ) values 
('7866cb79debf4345b4a8c7c12de2b7c1',	'kim.brugger@gmail.com',	'Kim Brugger',	'true');
