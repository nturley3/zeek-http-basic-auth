HTTP Basic Authentication Detection
======================

Bro module which detects the usage of Basic Authentication on HTTP services. 

Installation/Upgrade
------------

This is easiest to install through the Bro package manager::

	bro-pkg refresh
	bro-pkg install https://github.com/nturley3/zeek-http-basic-auth

If you need to upgrade the package::

	bro-pkg refresh
	bro-pkg upgrade https://github.com/nturley3/zeek-http-basic-auth

Usage
-----

This script generates the following notices: 

**HTTPBasicAuth::Found** - This indicates that an HTTP server was
seen using HTTP Basic authentication.
