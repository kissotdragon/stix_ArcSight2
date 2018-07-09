# stix_ArcSight2
A quick and dirty STIX/TAXII client that grabs STIX data from a TAXII discovery service, parses out the indicators and observables, and sends the data to ArcSight via CEF Syslog

# Requirements
This script was written to run in Python 2.7 and higher -- updated to use BeautifulSoup to parse the STIX document.  You could modify this script to use CABBY or the STIX libraries.  Some simple modifications are needed for it to work in Python 3 but I have not tested it.

This script requires some python dependencies.  You can install these using pip.

Needed modifications:
SET SYSLOG SERVER IP/PORT,
SET PROXY,
SET TIME DELTA,
SET COLLECTION NAME,
SET URL/USERNAME/PASSWORD

# Description

This is a script that connects to a TAXII servers discovery service, grabs the STIX document and parses out the indicators and observables. Specifically, this will parse IP's, Websites, Email Addresses, and Hash's. It takes the data creates a CEF message and sends is via syslog to a CEF syslog smartconnector. 

# Example Usage
## Import from TAXII Server

    python stix_ArcSight2.py

Copyright 2018 Intermountain Health Services

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
