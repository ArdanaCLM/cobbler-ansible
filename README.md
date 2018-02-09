(c) Copyright 2015-2017 Hewlett Packard Enterprise Development LP
(c) Copyright 2017-2018 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.


README
======

This repo contains the following roles:
- COBBLER: Cobbler server role

The verbs:
- configure
- install
- start
- populate

The operations:
- deploy

Repo structure:

```
├── bm-reimage.yml
├── cobbler-bm-verify.yml
├── cobbler-deploy.yml
├── cobbler-power-down.yml
├── cobbler-power-status.yml
├── cobbler-power-up.yml
├── cobbler-provision.yml
├── cobbler-set-diskboot-all.yml
├── cobbler-set-pxeboot-all.yml
├── cobbler-wait-for-shutdown.yml
├── cobbler-wait-for-ssh.yml
├── library
│   ├── bmconfig
│   └── ipmi
├── README.md
└── roles
    └── cobbler
        ├── defaults
        │   └── main.yml
        ├── files
        │   ├── cobbler.conf
        │   ├── configure_network.sh
        │   ├── fence_ipmitool.template
        │   └── validate_yaml
        ├── tasks
        │   ├── check-ipmi-connectivity.yml
        │   ├── configure.yml
        │   ├── get-nodelist.yml
        │   ├── install.yml
        │   ├── populate.yml
        │   ├── power-cycle-all.yml
        │   ├── power-down-all.yml
        │   ├── power-up-all.yml
        │   ├── set-diskboot-all.yml
        │   ├── set-pxeboot-all.yml
        │   ├── set-vars.yml
        │   ├── start.yml
        │   ├── verify-bm-install.yml
        │   ├── wait-for-shutdown.yml
        │   └── wait-for-ssh.yml
        ├── templates
        │   ├── cobbler.dhcp.template.j2
        │   ├── dhcpd.conf.j2
        │   ├── grub.cfg.j2
        │   ├── hlinux-server-vm.preseed.j2
        │   ├── isc-dhcp-server.j2
        │   ├── rhel73-anaconda-ks.cfg.j2
        │   └── settings.j2
        └── vars
            └── main.yml
```
