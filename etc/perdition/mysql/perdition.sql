drop table if exists tblPerdition;
create table tblPerdition (
  user char(16) not null primary key, 
  servername char(255) not null, 
  port char(8) default null
);
create index idxPerdition_user on tblPerdition (user);
insert into tblPerdition values ("dedel", "mail.freegates.be", "");
insert into tblPerdition values ("fred", "mail.nts.be", "1974");
insert into tblPerdition values ("tymm", "localhost",   "");
insert into tblPerdition values ("horms","localhost",   "");
