# Item Catalog
Application for item catalog with OAUTH support

## Pre requisites ##

You will need:
- Python >= 2.76
- Virtual Box with Vagrand configured

* Optionally, should be running in local machine, without virtual machine.

## Virtual Box and Vagrant ##

- Download and install Virtual Box: [Virtual Box](https://www.virtualbox.org/)
- Download and install Vagrant: [Vagrant](https://www.vagrantup.com/downloads.html)

## Configuring Vagrant ##

- Download this virtual Machine: [Base Virtual Machine](https://github.com/udacity/fullstack-nanodegree-vm)
- Unzip and go to directory and running with: `vagrant up`
- after that, run: `vagrant ssh`

## Running item Catalog ##

- Clone ItemCatalog repository
- Paste in vagrant folder
- up Vagrant: `vagrant up`
- Log in vagrant: `vagrant ssh`
- Go to vagrant directory: `cd /vagrant/`
- Go to ItemCatalog folder
- run: `python itemapplication.py`
