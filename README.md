# HTTP Basic Authentication Detection

## Purpose
Zeek module which detects the usage of basic authentication on HTTP services. 

## Installation/Upgrade

This script was tested using Zeek 3.0.11 and 4.0.3.

This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-http-basic-auth

If you need to upgrade the package:

	zkg refresh
	zkg upgrade https://github.com/nturley3/zeek-http-basic-auth

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

## Configuration

The config.zeek file gives Zeek admins the option to log passwords and to check only local networks.

## Generated Outputs

This script generates the following notices: 

| Notice Name | Description |
| -- | -- |
| HTTPBasicAuth::Found | This indicates that an HTTP server was seen using HTTP basic authentication. |

## Usage

Web applications using basic authentication tend to have less robust security. Often this authentication type is employed on IOT devices, servers with minimal security controls, or on development infrastructure. These also tend to use local accounts with no minimal password controls, no anti-brute force measures, and multi-factor authentication. The data this script produces clues in security analysts to potential security weak points.

This package pairs well with the [Zeek Pwned Credential](https://github.com/nturley3/zeek-pwned-credentials) package.

Tags: Threat hunting, hygiene

## About

Written by [@nturley3](https://github.com/nturley3).
