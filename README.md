# Applied-Security-CA-Project

# Setup

- Download the .ova files of all machines
- For each VM:
    - double-click on the .ova to import it in VirtualBox
    - select 'Include all network adapter MAC Addresses'
    - import
- The VMs all have aliases, they are 
    - Clark for the Client
    - Wynona for the Webserver
    - Dakota for the Database and CA
    - Benedict for the Backups
    - Grace for the sysadmin access Gateway
- The IP addresses for the internal network (and for the fake internet network) are static, and the /etc/hosts files of every machine contain the aliases for the IP addresses of the other (relevant) machines (e.g. doing `ping Dakota` from the Webserver will ping the Database machine).


# Network info
Network Addresses:

- intnet: Network 192.168.1.0/24
- ASL_internet: Network 192.168.2.0/24
- Dakota: 192.168.1.112
- Grace_internal: 192.168.1.114
- Grace_external: 192.168.2.114
- Benedict: 192.168.1.113
- Wynona_internal: 192.168.1.111
- Wynona_external: 192.168.2.111
- Clark: 192.168.2.200

# Credentials
The following format is used: `username:password`.

Client machine (Clark) user accounts:
- root:clark
- alex:alextheadmin
- ps:patrickschaller
- clark:lukasbruegger
- ms:michaelschlaepper
- a3:andresalan

Webserver machine (Wynona) user accounts:
- root:wynona
- wynona:wynona

Database and CA machine (Dakota) user accounts:
- root:dakota
- dakota:dakota

Backup machine (Benedict) user accounts:
- root:root

Gateway machine (Grace) user accounts:
- root:root
- sysadmin:root

# Config Info
The configuration files for both Wynona's and Dakota's webserver are located in `/etc/apache2/sites-availabe` on the respective machine. The Web directories are in `/var/www/imovies` and `/var/www/auth_manager` respectively. A copy of these two directories and of both config files can be found in this repository.


# General
To reach the Webserver from the client machine, just open a browser and type `https://imovies.asl.com` or `https://Wynona`. The only CA admin out of all the user is Patrick Schaller, so if you want to access the CA admin interface you need to use his account (and certificate-based authentication). We reccomend using Chrome as we have had problems importing our generated client-certificates into Firefox. If you want to use Firefox, we have found that importing a certificate into Chrome, then exporting it and importing that into Firefox will actually work.Other users (except for Lukas Bruegger) do not have a certificate installed already, so for the first login you will need to use credentials. To import the certificate you need to do it from inside the browsers settings, not by opening the .pfx file.

To access the internal network, you need to SSH from the client to the gateway using the alex account. When logged in as alex you can use `ssh sysadmin@Grace` to connect to it. Once inside the internal network, SSH access should work without password authentication from Grace to every machine.