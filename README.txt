IP FILTER MODULE FOR NGINX
==========================

The module uses a very efficient algorithm to match an IP address with a large
number of CIDR addresses. It uses a pre-generated database, filled from any
list of CIDR records with the following format:

  nnn.nnn.nnn.nnn/pp

Create a database
=================

First you need to download some CIDR files or define your list of CIDR records
to be inserted in the database. Finally use the CLI 'ipfiltercli' to create the
database as follows:

  1. Launch the CLI.

  ./ipfiltercli

  2. Type 'help' to learn commands ... then create the database.

  >>> createdb
  DB >>> load firewall_france.txt
  DB >>> insert 127.0.0.0/16
  DB >>> insert 10.0.0.0/16

  3. Make some Tests.

  DB >>> test 127.0.0.1/32
  [ matched ] elap: 0.000004 sec
  DB >>> test 8.8.8.8/32
  [not found] elap: 0.000004 sec

  4. Save the database to the binary format (file.db), then exit.

  DB >>> savedb database.db
  DB >>> exit

  Notes:
  You will use the database to implement a rule 'allow' or 'deny'. Therefore
  the content will depend of the rule you want apply.

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
      ipfilter_rule allow;                         # allow | deny
      ipfilter_denied_url "/403.html";             # denied url
      ipfilter_db /etc/nginx/modules/database.db;  # path of the database file
      ...

  4. Restart the server NGINX.

  At this point, the module has been enabled for the configured location(s).
  In the given example, only the request with IP that matches in the database
  are allowed to browse resources. Others are redirected to the denied url.   

