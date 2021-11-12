HTTP Basic Authentication Detection
======================
## Purpose
Zeek module which detects the usage of Basic Authentication on HTTP services. 

## Installation/Upgrade

This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-http-basic-auth

If you need to upgrade the package:

	zkg refresh
	zkg upgrade https://github.com/nturley3/zeek-http-basic-auth

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

## Configuration


## Usage


This script generates the following notices: 

**HTTPBasicAuth::Found** - This indicates that an HTTP server was
seen using HTTP Basic authentication.

## About

Written by [@nturley3](https://github.com/nturley3).