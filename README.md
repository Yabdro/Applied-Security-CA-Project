# Applied-Security-CA-Project

# How to import our project
- Download the .ova files of all 4 machines
- For each VM:
    - double-click on the .ova to import it in VirtualBox
    - select 'Include all network adapter MAC Addresses'
    - import
- The IP addresses for the internal network (and for the fake internet network) are static, known_hosts files are all complete with the IP addresses of the other (relevant) machines. (i.e. doing `ping Dakota` from Wynona will ping the Database machine)


# Network info
Network Addresses:

- intnet: Network 192.168.1.0/24
- ASL_internet: Network 192.168.2.0/24
- Dakota: 192.168.1.112
- Cate_internal: 192.168.1.114
- Cate_external: 192.168.2.114
- Benedict: 192.168.1.113
- Wynona_internal: 192.168.1.111
- Wynona_external: 192.168.2.111
- Clark: 192.168.2.200

# Credentials
For the following, this format will be used: `username:password`.

Client machine (Clark) user accounts:
- root:clark
- ps:patrickschaller
- clark:lukasbruegger
- ms:michaelschlaepper
- a3:andresalan

Webserver machine (Wynona) user accounts:
- root:wynona
- wynona:wynona

Database machine (Dakota) user accounts:
- root:dakota
- dakota:dakota

Backup machine (Benedict) user accounts:
- root:root

Gateway machine (Cate) user accounts:
- root:root
- sysadmin:root

# Config Info
The configuration files for both Wynona's and Dakota's webserver are located in `/etc/apache2/sites-availabe` on the respective machine. The Web directories are in `/var/www/imovies` and `/var/www/auth_manager` respectively. A copy of these two directories and of both config files can be found in this repository.


# General
To reach the Webserver from the client machine, just open a browser and type `https://imovies.asl.com` or `https://Wynona`. The only CA admin out of all the user is Patrick Schaller, so if you want to access the CA admin interface you need to use his account (and certificate-based authentication). We reccomend using Chrome as we have had problems importing our generated client-certificates into Firefox. If you really want to use Firefox, we have found that importing a certificate into Chrome, then exporting it and importing that into Firefox will actually work.Other users (except for Lukas Bruegger) do not have a certificate installed already, so for the first login you will need to use credentials.

Once inside the internal network, SSH access should work without password authentication from every machine, except for the Webserver (Wynona). SSH access from Wynona to other internal machines has been disabled for security purposes. For example, to access machine Dakota from inside Cate, you would execute `ssh root@Dakota`.