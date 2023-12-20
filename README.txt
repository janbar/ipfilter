IP FILTER MODULE FOR NGINX
==========================

The module uses a very efficient algorithm to match an IP address with a large
number of CIDR addresses. It uses a database, filled with list of CIDR records
with the following format:

  nnn.nnn.nnn.nnn/pp

The database can be used for other purposes than the nginx module. Here I
present its use with the module.

About the database
==================

The data format is binary form and optimized to store a bitmap tree. The search
time is constant and do not depends of the number of rules. Typical benchmark
with a database filled with 1 million rules report an average response time less
than 10 usec. In addition, database operations such as insert, update or delete
are extremely fast.

The only limit in terms of number of rules is the size of the database and the
memory available on the system. As an example, load all country subnets of US
UK DE and FR, so 500K rules (Dec 2023), increases the database to 6 MB.

The database is administred using the command line 'ipfiltercli'. Loading or
updating the rules can be made on the fly without need to stop consumers.

Create a database
=================

First you need to download some CIDR files or define your list of CIDR records
to fill the database. Finally use the CLI 'ipfiltercli' to create or
update the database as follows:

  1. Launch the CLI.

  ./ipfiltercli

  2. Type 'help' to learn commands ... then create the database.

  >>> create database.db
  noname >>> setname DB1
  DB1 >>> load allow firewall_france.txt
  DB1 >>> allow 127.0.0.0/16
  DB1 >>> allow 10.0.0.0/16
  DB1 >>> load deny firewall_denied.txt
  ...

  3. Make some Tests.

  DB1 >>> test 127.0.0.1/32
  [ allow ] elap: 0.000004 sec
  DB1 >>> test 8.8.8.8/32
  [ empty ] elap: 0.000004 sec

  4. Quit the CLI.

  DB1 >>> exit

  Notes:
  Empty result are denied by default.

Configure the module for NGINX
==============================

  1. Copy the module 'ngx_http_ipfilter_module.so' and your database file(s)
     in place, i.e /etc/nginx/modules/.

  2. Edit the nginx.conf to load the module.

  load_module /etc/nginx/modules/ngx_http_ipfilter_module.so;

  3. Edit the sites configution to enable/configure the module per location.
     You can share a database with many locations, and use dedicated databases
     for few locations.

  location / {
      ipfilter_enabled;                            # enable the module
      ipfilter_denied_url "/403.html";             # denied url
      ipfilter_db /etc/nginx/modules/database.db;  # path of the database file
      ...

  If the denied url is not configured, you can test the variable '$ipfilter'
  to rewrite the flow. It contains one of the following values:

     0=Not found, 1=Allow, 2=Deny or 3=Error.

  4. Restart the server NGINX.

  At this point, the module has been enabled for the configured location(s).
  In the given example, only the request with allowed IP in the database are
  allowed to browse resources. Others are redirected to the denied url.

Update the database
===================

  The database can be updated on the fly using the CLI. Therefore no need
  to stop/restart NGINX.

  1. Launch the CLI.

  ./ipfiltercli

  2. Mount the database to update.

  mount /etc/nginx/modules/database.db

  3. Use allow, deny, load ...

  allow  10.1.0.0/16

  Notes:
  Updates are applied instantly.
