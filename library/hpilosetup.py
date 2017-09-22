#!/usr/bin/env python
#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
# Copyright 2017 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import print_function
import argparse
import json
import sys
# Need six > 1.3.0 (1.8.0 works)
import six
import urllib3
try:
    urllib3.disable_warnings(urllib3.exceptions.InsecurePlatformWarning)
except:
    pass

from proliantutils.ilo import ribcl

from httplib import HTTPSConnection
from base64 import b64encode


def do_raw_cmd(cmd, hostname, path, headers, data=None):
    conn = HTTPSConnection(host=hostname, strict=True)
    conn.request(cmd, path, headers=headers, body=data)
    resp = conn.getresponse().read()
    return resp


def do_raw_get(hostname, path, headers):
    return do_raw_cmd('GET', hostname, path, headers)


def do_raw_patch(hostname, path, headers, data):
    return do_raw_cmd('PATCH', hostname, path, headers, data)


def set_propagate_time(ilo_client, val='N'):
    """
       Set PROPAGATE_TIME_TO_HOST configuration item
       If this is set, then the iLO can set the time on the host
       on powerup, and, if the iLO is misconfigured, the host can
       encounter time jumps that cause issues with other apps,
       including at installation time.
    """
    import xml.etree.ElementTree as etree
    xml = ilo_client._create_dynamic_xml('MOD_GLOBAL_SETTINGS',
                                         'RIB_INFO', 'write')
    if six.PY2:
        child_iterator = xml.getiterator()
    else:
        child_iterator = xml.iter()
    for child in child_iterator:
        if child.tag == 'MOD_GLOBAL_SETTINGS':
            etree.SubElement(child, 'PROPAGATE_TIME_TO_HOST', VALUE=val)
    d = ilo_client._request_ilo(xml)
    data = ilo_client._parse_output(d)
    return data


def get_propagate_time(ilo_client):
    """
       Get PROPAGATE_TIME_TO_HOST configuration item
    """
    info = ilo_client._execute_command('GET_GLOBAL_SETTINGS',
                                       'RIB_INFO', 'read')
    res = info['GET_GLOBAL_SETTINGS']['PROPAGATE_TIME_TO_HOST']
    return res['VALUE']


def set_tz(ilo_client, val):
    """
       Set TIMEZONE configuration item
    """
    import xml.etree.ElementTree as etree
    xml = ilo_client._create_dynamic_xml('MOD_NETWORK_SETTINGS',
                                         'RIB_INFO', 'write')
    if six.PY2:
        child_iterator = xml.getiterator()
    else:
        child_iterator = xml.iter()
    for child in child_iterator:
        if child.tag == 'MOD_NETWORK_SETTINGS':
            etree.SubElement(child, 'TIMEZONE', VALUE=val)
    d = ilo_client._request_ilo(xml)
    data = ilo_client._parse_output(d)
    return data


def error(msg):
    print(msg, file=sys.stderr)


def verbose(msg):
    print(msg, file=sys.stderr)


def output(msg):
    print(msg, file=sys.stderr)


def setup_ilo(user, password, host, tz=None,
              bootmode=None, check_privs=True,
              check_propagate=True,
              boot_from_dev=None,
              do_verbose=True, debug=False):
    """
        Connect to a host to valdiate its iLO settings.
        If the host doesnt support ilo/ribcl return 1
        else
            report on firmware settings
            optionally check the privileges
            optionally set the timezone
            check NTP propagate setting
            check bootmode and optionally set it
    """
    # Make a connection
    try:
        if (do_verbose):
            verbose('Connecting to %s' % host)
        ilo_client = ribcl.IloClient(host, user, password)
        # if we cant get at least power status we stop.
        ilo_client.get_host_power_status()
    except ribcl.IloConnectionError as e:
        error('Error(%s) connecting to %s: %s' % (type(e), host, e))
        return 1
    except Exception as e:
        error('Error(%s) connecting to %s: %s' % (type(e), host, e))
        return 1

    auth = 'BASIC ' + b64encode(user + ':' + password)
    headers = {'Authorization': auth, 'Content-Type': 'application/json'}

    mp = None
    try:
        if (do_verbose):
            verbose('Getting f/w version')
        info = ilo_client._execute_command('GET_FW_VERSION',
                                           'RIB_INFO',
                                           'read')
        if (debug):
            verbose(info.keys())
        for key in info['GET_FW_VERSION'].keys():
            output("%s: %s" % (key, info['GET_FW_VERSION'][key]))
        # e.g.: 'iLO3' or 'iLO4'
        mp = info['GET_FW_VERSION'].get('MANAGEMENT_PROCESSOR')
    except Exception as e:
        error('Error(%s) getting f/w version from %s: %s' %
              (type(e), host, e))

    # Get the user privileges - fail if the check was requested and
    # if the required privileges arent present.
    # Its useful to fail early if you get a user without Administrator privs
    if check_privs:
        try:
            if (do_verbose):
                verbose('Getting user info')
            user_dict = {'USER_LOGIN': user}
            info = ilo_client._execute_command('GET_USER',
                                               'USER_INFO',
                                               'read',
                                               user_dict)
            if ('CONFIG_ILO_PRIV' in info['GET_USER']):
                if (info['GET_USER']['CONFIG_ILO_PRIV'] != 'Y'):
                    error('Insufficient privs: CONFIG_ILO_PRIV is required')
                    for key in info['GET_USER'].keys():
                        verbose("%s: %s" % (key, info['GET_USER'][key]))
                    return 1
            else:
                # Maybe its an older iLO?
                pass
        except Exception as e:
            error('Error(%s) getting user info from %s: %s' %
                  (type(e), host, e))

    # Get the timezone - dont fail if it cant be read.
    # UTC is NOT a valid timezone for iLO. Africa/Accra?
    if (do_verbose):
        verbose('Getting network settings')
    try:
        info = ilo_client._execute_command('GET_NETWORK_SETTINGS',
                                           'RIB_INFO',
                                           'read')
        now_tz = info['GET_NETWORK_SETTINGS']['TIMEZONE']['VALUE']
        verbose('Current timezone is: %s' % tz)
        if (tz and now_tz != tz):
            if (do_verbose):
                verbose('Setting timezone=%s' % tz)
            try:
                set_tz(ilo_client, tz)
            except Exception as e:
                error('Error(%s) setting tz %s for %s: %s' %
                      (type(e), args.tz, args.host, e))
    except Exception as e:
        error('Error(%s) getting tz for %s: %s' %
              (type(e), host, e))

    # Get the propagate flag - dont fail if it cant be read.
    if (do_verbose):
        verbose('Getting global settings')
    try:
        propagate = get_propagate_time(ilo_client)
        verbose('Current time propagate setting is: %s' % propagate)

        if check_propagate and propagate != 'N':
            if (do_verbose):
                verbose('Setting time propagate OFF')
            try:
                set_propagate_time(ilo_client, 'N')
            except Exception as e:
                error('Error(%s) setting time propagate %s for %s: %s' %
                      (type(e), host, e))
            propagate = get_propagate_time(ilo_client)
            if propagate != 'N':
                verbose('Failed setting time propagate OFF')
    except Exception as e:
        error('Error(%s) getting time propagate for %s: %s' %
              (type(e), host, e))

    # bootmode = 'LEGACY'
    current_mode = None
    pending_mode = None
    if mp and mp == 'iLO4':
        try:
            # GET_SUPPORTED_BOOT_MODE = LEGACY_ONLY, UEFI_ONLY,
            #                           LEGACY_UEFI, UNKNOWN
            supported_modes = ilo_client.get_supported_boot_mode()
            if (do_verbose):
                verbose("Supported modes are: %s" % supported_modes)
            # Possible return values are LEGACY, UEFI, or UNKNOWN
            current_mode = ilo_client.get_current_boot_mode()
            pending_mode = ilo_client.get_pending_boot_mode()
            if (do_verbose):
                verbose("Current boot mode is: %s" % current_mode)
                verbose("Pending boot mode is: %s" % pending_mode)
            if bootmode is not None:
                if pending_mode != bootmode:
                    try:
                        if (do_verbose):
                            verbose("Setting *next* boot mode as: %s" %
                                    bootmode)
                        ilo_client.set_pending_boot_mode(bootmode)
                    except Exception as e:
                        error('Error(%s) setting boot_mode to %s for %s: %s' %
                              (type(e), bootmode, host, e))
        except ribcl.IloError as e:
            if 'Feature not supported' in repr(e):
                error(e)
        except Exception as e:
            error('Error(%s) getting current boot mode for %s: %s' %
                  (type(e), host, e))

    _process_bootmode(ilo_client, host, headers, boot_from_dev,
                      current_mode, pending_mode, do_verbose, debug)

    return 0


def _update_boot_order(ilo_client, host, headers, boot_order,
                       boot_from_dev, current_mode):
    if current_mode == 'UEFI':
        offset = 0
        for item in boot_order:
            if item == boot_from_dev:
                break
            offset += 1
        if offset < len(boot_order) and offset != 0:
            tosend = {'PersistentBootConfigOrder':
                      boot_order}
            master = tosend['PersistentBootConfigOrder'][offset]
            del tosend['PersistentBootConfigOrder'][offset]
            tosend['PersistentBootConfigOrder'].insert(0, master)
            resp = do_raw_patch(host,
                                '/rest/v1/Systems/1/BIOS/Boot/Settings',
                                headers,
                                json.dumps(tosend))
            result = json.loads(resp)
            if 'Messages' in result:
                for message in result['Messages']:
                    if "MessageID" in message:
                        verbose('Boot order update completed with status: %s'
                                % message["MessageID"])
            else:
                error('Unexpected status received while setting boot order')
            # expect this response
            # {"Messages":[{"MessageID":"iLO.0.10.SystemResetRequired"}],
            #               "Name":"Extended Error Information",
            #               "Type":"ExtendedError.0.9.5"}
            #
            # and so no point in trying to GET the current value after setting
            # to check as the system must be reset.
        else:
            verbose("boot_from_dev value (%s) is invalid" % boot_from_dev)
    else:
        offset = 0
        for item in boot_order:
            if item['value'] == boot_from_dev:
                break
            offset += 1
        if offset < len(boot_order) and offset != 0:
            master = boot_order[offset]
            del boot_order[offset]
            boot_order.insert(0, master)
            resp = ilo_client._get_persistent_boot()
            # ilo_client.update_persistent_boot will fail on 'USB', so use _set
            resp = ilo_client._set_persistent_boot(
                [item['value'] for item in boot_order
                 if item['value'] != 'Unknown'])
        else:
            verbose("boot_from_dev value is either invalid or the default")


def _list_uefi_boot_order(host, headers, do_verbose=True, debug=True):
    try:
        # Use the HP Rest interface to get and set boot order
        newbios = json.loads(do_raw_get(host,
                                        '/rest/v1/Systems/1/BIOS/Boot',
                                        headers))
        if debug:
            verbose(newbios)
        for source in newbios['PersistentBootConfigOrder']:
            verbose("\t%s" % (source))
        verbose('Valid boot sources are:')
        for source in newbios['BootSources']:
            verbose('\t%s: \"%s\"' % (source['StructuredBootString'],
                                      source['BootString']))
        return newbios['PersistentBootConfigOrder']
    except:
        pass


def _list_legacy_boot_order(ilo_client, current_mode,
                            do_verbose=True, debug=True):
    try:
        info = ilo_client._execute_command('GET_PERSISTENT_BOOT',
                                           'SERVER_INFO', 'read')
        boot_order = info['PERSISTENT_BOOT']['DEVICE']

        # boot_order is an ordered list of dicts with key 'value'
        # if 'DESCRIPTION' in boot_order[0]: then its a UEFI list
        if debug:
            verbose(json.dumps(boot_order, indent=2))
        for item in boot_order:
            if current_mode == 'UEFI' and 'DESCRIPTION' in item:
                verbose("\t%s: %s" % (item['value'],
                                      item['DESCRIPTION']))
            else:
                verbose("\t%s" % (item['value']))
        return boot_order
    except:
        pass


def _process_bootmode(ilo_client, host, headers, boot_from_dev,
                      current_mode, pending_mode, do_verbose, debug):
    # Note on boot settings:
    #    LEGACY BIOS and UEFI BIOS treat boot order separately and differently
    #
    #    LEGACY BIOS:
    #        The boot order can be set via ilo to a list
    #              e.g. CDROM USB HDD NETWORK
    #        The relative order of the network devices can be set using
    #        a POST to a json interface
    #              NETWORK1 NETWORK2 NETWORK3 ...
    #              **not implemented**
    #              allowable values are CDROM USB HDD NETWORK
    #        It is NOT possible in LEGACY BIOS to *programmatically*
    #              list devices
    #              determine what device is NETWORK1,2 etc
    #              enable a device for network boot
    #              determine what devices have links connected
    #
    #    UEFI
    #        The boot order can be found via ilo api call GET_PERSISTENT_BOOT
    #        The boot order can be found via json api call /json/boot_order
    #        The boot order can be set via ilo api call
    #        The boot order can be set explictly using POST to a json interface
    #              Boot000A, etc ...
    #              HD.Emb.1.3 NIC.FlexLOM.1.1.IPv4 NIC.LOM.1.1.IPv4
    #              These names can be mapped to devices via GET_PERSISTENT_BOOT
    #        It is NOT possible in UEFI mode to *programmatically*
    #              enable a device for network boot
    #              determine what devices have links connected
    #

    # This request can be used to list all network devices, BUT doesnt return
    # link status, or if network boot enabled, just port, location and mac addr
    resp = ilo_client.get_host_health_data()
    nic_info = resp['GET_EMBEDDED_HEALTH_DATA'].get('NIC_INFORMATION', None)
    if nic_info:
        nics = nic_info['NIC']
    else:
        nics = []
        verbose('No NIC information for this host')
    if debug:
        verbose(json.dumps(nics, indent=2))

    if len(nics) > 0:
        verbose('Found NICs on system')
    for item in nics:
        verbose('\tMAC: %s LOCATION: %s PORT: %s' %
                (item['MAC_ADDRESS']['VALUE'],
                 item['LOCATION']['VALUE'],
                 item['NETWORK_PORT']['VALUE']))

    if boot_from_dev:
        try:
            if (do_verbose):
                verbose('Listing persistent boot order:')
            if current_mode == 'UEFI':
                boot_order = _list_uefi_boot_order(host, headers,
                                                   do_verbose, debug)
            else:
                boot_order = _list_legacy_boot_order(ilo_client, current_mode,
                                                     do_verbose, debug)
            if boot_from_dev != '?':
                if (do_verbose):
                    verbose('Updating boot device')
                if pending_mode != current_mode:
                    error("Changing boot order when pending boot mode (%s) is "
                          "not the same as current mode (%s) is not possible" %
                          (pending_mode, current_mode))
                else:
                    _update_boot_order(ilo_client, host, headers,
                                       boot_order, boot_from_dev, current_mode)
        except Exception as e:
            error('Error(%s) getting persistent boot for %s: %s' %
                  (type(e), host, e))

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Utility to setup HP iLO')
    parser.add_argument('-U', '--user', required=True, help='Username')
    parser.add_argument('-P', '--password', required=True, help='Password')
    parser.add_argument('-H', '--host', required=True, help='Host')
    parser.add_argument('-c', '--check_privs', action='store_true',
                        help='Check iLO privs')
    parser.add_argument('-t', '--check_propagate_time', action='store_true',
                        help='Check iLO propagate time to BIOS setting is OFF')
    parser.add_argument('-z', '--tz', default=None, help='TimeZone')
    parser.add_argument('-m', '--bootmode', default=None, help='iLO4 bootmode')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    parser.add_argument('-n', '--boot_from_dev', default=None,
                        help="""Device from which to boot.
    For LEGACY systems the allowable values are CDROM HDD USB NETWORK.
    This utility cannot determine the Nic names associated with NETWORK,
    or the order of the NETWORK (PXE-enabled) Nics.
    For UEFI systems the allowable values can be determined from the system
    by running this command with a value for this argument of ?
    For example: 'NIC.FlexLOM.1.1.IPv4'""")
    parser.add_argument('--boot-from-dev', dest='boot_from_dev')

    args = parser.parse_args()

    if (args.debug):
        # Need six > 1.3.0 (1.8.0 works)
        verbose(six.__version__)

    setup_ilo(args.user, args.password, args.host,
              args.tz, args.bootmode, args.check_privs,
              args.check_propagate_time,
              args.boot_from_dev,
              args.verbose, args.debug)

    sys.exit(0)
