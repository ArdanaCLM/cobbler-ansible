#!/usr/bin/env python
#
# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
# (c) Copyright 2017 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""update_fcoe_udev.py

Provides tooling that can be used to manage the persistent ordering of
network devices for use with FCOE deployments.

Usage:
    update_fcoe_udev.py [--prefix|-p <prefix>]

Where:
    --prefix, -p <prefix>
        specifies the path to prefix system file access with.

Example:
    When running during a preseed install, the installed system
hierarchy is mounted under /target, so invoke the command as follows:

    % update_fcoe_udev.py -p /target
"""


from argparse import ArgumentParser
from collections import OrderedDict
from glob import glob
from hashlib import md5 as hasher
from operator import attrgetter, itemgetter
import os
import re
import sys


class ArdanaSystemPathsError(RuntimeError):
    def __init__(self, *args, **kwargs):
        super(ArdanaSystemPathsError, self).__init__(*args, **kwargs)


class DictReplacerError(RuntimeError):
    def __init__(self, *args, **kwargs):
        super(DictReplacerError, self).__init__(*args, **kwargs)


class ConfFileError(RuntimeError):
    def __init__(self, *args, **kwargs):
        super(ConfFileError, self).__init__(*args, **kwargs)


class PhaseRenameError(ConfFileError):
    def __init__(self, *args, **kwargs):
        super(PhaseRenameError, self).__init__(*args, **kwargs)


class NetRulesError(RuntimeError):
    def __init__(self, *args, **kwargs):
        super(NetRulesError, self).__init__(*args, **kwargs)


class NotRuleError(NetRulesError):
    def __init__(self, *args, **kwargs):
        super(NotRuleError, self).__init__(*args, **kwargs)


class NotRule70Error(NetRulesError):
    def __init__(self, *args, **kwargs):
        super(NotRule70Error, self).__init__(*args, **kwargs)


class NotRule71Error(NetRulesError):
    def __init__(self, *args, **kwargs):
        super(NotRule71Error, self).__init__(*args, **kwargs)


class RenameError(NetRulesError):
    def __init__(self, *args, **kwargs):
        super(RenameError, self).__init__(*args, **kwargs)


class InvalidRuleError(NetRulesError):
    def __init__(self, *args, **kwargs):
        super(InvalidRuleError, self).__init__(*args, **kwargs)


class InvalidDeviceNameError(NetRulesError):
    def __init__(self, *args, **kwargs):
        super(InvalidDeviceNameError, self).__init__(*args, **kwargs)


class ArdanaSystemPaths(object):
    """Helper class for system path access.

    Implements a simple helper class used to manage access the important
    system paths, potentially accessed under a provided offset, e.g.
    during an install.
    """
    _default_path_prefix = "/"
    _default_flag_dir = "/etc/ardana"
    _default_flag_name = "udev_net_rules_updated"
    _rules_file_70 = "/etc/udev/rules.d/70-persistent-net.rules"
    _rules_file_71 = "/etc/udev/rules.d/71-persistent-net.rules"
    _fcoe_dir = "/etc/fcoe"
    _ifaces_file = "/etc/network/interfaces"
    _ifaces_dir = "/etc/network/interfaces.d"

    def __init__(self, prefix=None, sys_prefix=None, flag_dir=None,
                 flag_name=None):
        """Initialise instance settings.

        The prefix argument specifies an offset path for all path
        resolution, e.g. /target if invoked during preseed install.
        The flag_dir and flag_name combined specify a flag file, the
        presence of which indicates that the associated operations
        have already been performed.
        """
        if prefix is None:
            prefix = self._default_path_prefix
        if sys_prefix is None:
            sys_prefix = self._default_path_prefix
        if flag_dir is None:
            flag_dir = self._default_flag_dir
        if flag_name is None:
            flag_name = self._default_flag_name

        if not os.path.exists(prefix):
            raise ArdanaSystemPathsError("Prefix '%s' doesn't exist!" %
                                         prefix)
        self._path_prefix = prefix
        self._path_sys_prefix = sys_prefix
        self._flag_dir = flag_dir
        self._flag_name = flag_name

    @property
    def prefix(self):
        """Expose prefix path as readonly attr."""
        return self._path_prefix

    @prefix.setter
    def prefix(self, prefix):
        """Update the prefix path to a new value."""
        self._path_prefix = prefix

    def system_path(self, path):
        """Returns the actual path to use to access specified path."""
        return os.path.join(self.prefix, path.lstrip('/'))

    @property
    def sys_prefix(self):
        """Expose sys_prefix path as readonly attr."""
        return self._path_sys_prefix

    @sys_prefix.setter
    def sys_prefix(self, sys_prefix):
        """Update the sys_prefix path to a new value."""
        self._path_sys_prefix = sys_prefix

    def system_sys_path(self, *args):
        """Returns the actual path to use to access specified path."""
        return os.path.join(self.sys_prefix, "sys", *args)

    @property
    def rules_file_70(self):
        """System path to persistent udev rules file."""
        return self.system_path(self._rules_file_70)

    @property
    def rules_file_71(self):
        """System path to persistent udev rules file."""
        return self.system_path(self._rules_file_71)

    @property
    def fcoe_dir(self):
        """System path to FCOE config directory."""
        return self.system_path(self._fcoe_dir)

    @property
    def ifaces_file(self):
        """System path to network interfaces config file."""
        return self.system_path(self._ifaces_file)

    @property
    def ifaces_dir(self):
        """System path to network interfaces config directory."""
        return self.system_path(self._ifaces_dir)

    @property
    def flag_dir(self):
        """System path to directory holding flag files."""
        return self.system_path(self._flag_dir)

    @property
    def flag_name(self):
        """Expose flag name as readonly attr."""
        return self._flag_name

    @property
    def flag_file(self):
        """System path to specified flag file."""
        return os.path.join(self.flag_dir, self.flag_name)

    @property
    def flag_exists(self):
        """True if specified flag file exists."""
        return os.path.exists(self.flag_file)


class DictReplacer(object):
    """Manage text replacement based upon lookup table.

    Instances of this class can be used to manage updating contents
    of lines where the replacement value is dynamically looked up
    in a provided dictionary, based on the value to be replaced; if
    no value is found in provided dictionary then leave unchanged.
    """

    def __init__(self, replacer, lookup, field=1, skipper=None):
        """Initialise the instance settings.

        The replacer argument must include at least one group
        specifier identifying the value to be replaced.
        The lookup argument must be a dictionary line object that
        maps candidate values onto there replacements.
        The field argument specifies which group's value should be
        looked up in the lookup map when doing replacement.
        The skipper argument can optionally specify a pattern that
        can be used to skip processing, e.g. ignore comment or
        blank lines.
        NOTE: The replacer and skipper can be provided as either
        compiled pattern objects, or pattern strings which will be
        automatically compiled, and the compiled versions used.
        """
        if isinstance(replacer, str):
            replacer = re.compile(replacer)
        if isinstance(skipper, str):
            skipper = re.compile(skipper)

        if not replacer.groups:
            raise DictReplacerError("Invalid replacer pattern: no groups "
                                    "specified - '%s'" % replacer.pattern)

        self._replacer = replacer
        self._lookup = lookup
        self._field = field
        self._skipper = skipper

    @property
    def replacer(self):
        """Expose replacer as a readonly attr."""
        return self._replacer

    @property
    def lookup(self):
        """Expose lookup as a readonly attr."""
        return self._lookup

    @property
    def field(self):
        """Expose field as a readonly attr."""
        return self._field

    @property
    def skipper(self):
        """Expose skipper as a readonly attr."""
        return self._skipper

    def should_skip(self, text):
        """Check if we should skip processing of this text.

        Returns true if a skipper pattern has been provided, and
        the pattern matches the specified value.
        """
        return self.skipper and self.skipper.match(text)

    def _callback(self, matcher):
        """Callback handling lookup of the substitution value."""
        matched_field = matcher.group(self.field)
        replacement = self.lookup.get(matched_field)
        if not replacement:
            return matcher.group(0)

        fields = list(f or "" for f in matcher.groups())
        fields[self.field - 1] = replacement

        return "".join(fields)

    def replace(self, text):
        """Replace content in text based upon lookup table.

        Based upon the content of the associated lookup table,
        replace any occurrences of any matching keys with their
        associated values that may be found in the provided text.
        """
        if self.should_skip(text):
            return text
        return self.replacer.sub(self._callback, text)


class ConfEntry(object):
    """Basic Conf File Entry handler."""
    def __init__(self, line, lineno, syspaths):
        """Record line and line number."""
        self._line = line
        self._lineno = lineno
        self._orig_line = None
        self._syspaths = syspaths

    def __str__(self):
        """Return line as str() value."""
        return self._line

    @property
    def syspaths(self):
        """Syspaths object to use when resolving paths."""
        return self._syspaths

    @property
    def lineno(self):
        """Line number of this line in the file."""
        return self._lineno

    @property
    def orig_line(self):
        """Original line content."""
        if self._orig_line is None:
            return self._line
        return self._orig_line

    def _backup_line(self):
        """Backup line content if not previously done."""
        if self._orig_line is None:
            self._orig_line = self._line

    def update(self, new_line):
        """Update line with new content, backing up if needed."""
        if new_line == self._line:
            return

        self._backup_line()
        self._line = new_line

    @property
    def dirty(self):
        """True if line has in fact been modified."""
        return self._orig_line is not None


class UdevNetEntry(ConfEntry):
    """Manage Udev persistent network rule entry.

    Class used to manage a specific udev persistent net rules,
    allowing renaming of associated device and checking whether
    the device exists on the system, and whether the configured
    settings match the actual settings in use..
    """

    def __init__(self, line, lineno, syspaths):
        """Record line and line number, and parse fields from line."""
        super(UdevNetEntry, self).__init__(line, lineno, syspaths)
        self._orig_dev_name = None
        self._fields = self._parse_line()

    def _parse_line(self):
        """Parse line into fields, skipping comment and blank lines."""
        # check if line contains a rule or not
        stripped = self._line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        # strip out double quotes from values, and simplify equals strings
        simplified = self._line.replace("==", "=").replace('"', '')

        # return a dictionary formed from the key=value pairs found in line
        return dict(f.strip().split("=", 1) for f in simplified.split(","))

    def _backup_dev_name(self):
        """Backup original device name if not previously done."""
        if self._orig_dev_name is None:
            self._orig_dev_name = self.dev_name

    @property
    def is_rule(self):
        """True if line represents a udev rule."""
        return self._fields is not None

    @property
    def mac(self):
        """Expose parsed MAC address as a readonly attr."""
        if not self.is_rule:
            raise NotRuleError("No 'ATTR{address}' field.")

        if "ATTR{address}" not in self._fields:
            raise NotRule70Error("No 'ATTR{address}' field.")

        return self._fields["ATTR{address}"]

    @property
    def dev_name(self):
        """Expose parsed device name as a readonly attr."""
        if not self.is_rule:
            raise NotRuleError("No 'NAME' field.")

        return self._fields["NAME"]

    _name_re = re.compile(r"^(\D+)(\d+)$")

    @property
    def is_dev_name_valid(self):
        """True if device name is valid format."""
        return self._name_re.match(self.dev_name) is not None

    @property
    def dev_name_prefix(self):
        """Device name prefix string.

        Expose the device name prefix string, e.g. eth for ethN,
        as a readonly attr.
        """
        match = self._name_re.match(self.dev_name)
        if not match:
            raise InvalidDeviceNameError("Not a valid device name: '%s'" %
                                         self.dev_name)

        return match.group(1)

    @property
    def orig_dev_name(self):
        """Expose original device name as a readonly attr."""
        if not self.is_rule:
            raise NotRuleError("No original name to find.")

        if self._orig_dev_name:
            return self._orig_dev_name

        return self.dev_name

    _dev_rename_re = re.compile(r'(\sNAME=")([^"]+)(")')

    def dev_rename(self, new_dev_name):
        """Rename device associated with rule.

        Rename the device associated with a given rule, if the
        name has in fact changed, and the device hasn't already
        been re-ordered.
        """
        if not self.is_rule:
            raise NotRuleError("Rename not possible.")

        if new_dev_name == self.dev_name:
            return

        if self.reordered:
            return

        self._backup_dev_name()

        repl_value = r'\1' + new_dev_name + r'\3'
        new_line, count = self._dev_rename_re.subn(repl_value,
                                                   self._line, 1)
        if not count:
            raise InvalidRuleError("Failed to update NAME field")

        self.update(new_line)
        self._fields["NAME"] = new_dev_name

    @property
    def sys_class_orig_path(self):
        """Expose path to original /sys/class/net entry as readonly attr."""
        if not self.is_rule:
            raise NotRuleError("Cannot determine /sys/class/net path")

        return self.syspaths.system_sys_path('class/net', self.orig_dev_name)

    @property
    def sys_class_path(self):
        """Expose path to current /sys/class/net entry as readonly attr."""
        if not self.is_rule:
            raise NotRuleError("Cannot determine /sys/class/net path")

        return self.syspaths.system_sys_path('class/net', self.dev_name)

    @property
    def sys_path_exists(self):
        """True if original /sys/class/net path exists."""
        return os.path.exists(self.sys_class_orig_path)

    @property
    def sys_dev_port(self):
        """The PCI device port of the device associated with this rule.

        Expose PCI Device port associated with original device name as
        readonly attr.
        """
        try:
            with open(os.path.join(self.sys_class_orig_path, "dev_port")) as f:
                dev_port = f.read().strip('\0').strip()
        except Exception:
            sys.stderr.write("Failed to read dev_port for entry: %s\n" %
                             (self._orig_line))
            raise

        return dev_port

    @property
    def dev_port(self):
        """The ATTR{dev_port} specified in this rule."""
        if not self.is_rule:
            raise NotRuleError("No 'ATTR{dev_port}' field.")

        if "ATTR{dev_port}" not in self._fields:
            raise NotRule71Error("No 'ATTR{dev_port}' field.")

        return self._fields["ATTR{dev_port}"]

    @property
    def devpath(self):
        """The DEVPATH specified in this rule."""
        if not self.is_rule:
            raise NotRuleError("No 'DEVPATH' field.")

        if "DEVPATH" not in self._fields:
            raise NotRule71Error("No 'DEVPATH' field.")

        return self._fields["DEVPATH"]

    @property
    def sys_mac(self):
        """The system MAC address associated with rules current device.

        Expose the MAC address associated with the current device name
        as a readonly attr. Used in determining if network devices have
        already been re-ordered.
        """
        try:
            with open(os.path.join(self.sys_class_path, "address")) as f:
                sys_mac = f.read().strip('\0').strip()
        except Exception:
            sys.stderr.write("Failed to read address for entry: %s\n" %
                             (self._orig_line))
            raise

        return sys_mac

    @property
    def pci_dev(self):
        """The PCI device ID associated with rules network device.

        Expose the PCI Device ID associated with the original device
        name as a readonly attr.
        """
        return os.path.realpath(self.sys_class_orig_path).split("/")[-3]

    @property
    def pci_order(self):
        """Returns constructed PCI ordering string for use in sorting."""
        return "%s:%s" % (self.pci_dev, self.sys_dev_port)

    @property
    def reordered(self):
        """Has this rule already been re-ordered.

        True if device associated with has already been reordered,
        either by us or a previous run.
        """
        if "ATTR{address}" in self._fields:
            return self.mac != self.sys_mac

        if "DEVPATH" in self._fields:
            return self.devpath != ("*/%s/*" % self.pci_dev)


class ConfFile(object):
    """Class used to manage on-disk config files"""

    def __init__(self, conf_file, syspaths, handler=None):
        """Initialise instance settings.

        If no handler specified, use default, i.e. ConfEntry.
        Track name changes for conf file via path list.
        """
        if handler is None:
            handler = ConfEntry

        self._path = [conf_file]
        self._rename_phase = 0
        self._handler = handler

        self._lines = []
        self._linemap = {}
        self._syspaths = syspaths

    @property
    def syspaths(self):
        """System paths manager to use when resolving paths."""
        return self._syspaths

    @property
    def path(self):
        """Current file path."""
        return self._path[-1]

    @path.setter
    def path(self, new_path):
        """Change file path to new name."""
        if new_path == self.path:
            return

        self._path.append(new_path)

    @property
    def paths(self):
        """Expose rename paths list as readonly attr."""
        return tuple(self._path)

    @property
    def orig_path(self):
        """Expose original file path as readonly attr."""
        return self._path[0]

    @property
    def rename_phases(self):
        """Total number of renames for this conf file."""
        return len(self._path) - 1

    @property
    def has_moved(self):
        """True if a file has been renamed."""
        return bool(self.rename_phases)

    @property
    def renames_remaining(self):
        """Number of outstanding rename operations.

        Remaining number of renames for this conf file that
        haven't yet been performed.
        """
        return self.rename_phases - self._rename_phase

    @property
    def rename_phase_src(self):
        """Source path for current rename phase."""
        return self._path[self._rename_phase]

    @property
    def rename_phase_dst(self):
        """Destination path for current rename phase."""
        if not self.renames_remaining:
            raise PhaseRenameError("File '%s' already fully renamed to '%s'"
                                   % (self.orig_path, self.path))
        return self._path[self._rename_phase + 1]

    def _load_file(self):
        """Load entries from on-disk file.

        Load the conf file lines each as an instance of provided
        handler, and record associated line number mapping.
        """
        try:
            with open(self.path) as f:
                conf_lines = f.readlines()
        except Exception:
            sys.stderr.write("open('%s') failed: %s\n" %
                             (self.path, sys.exc_info()[1]))
            raise

        for lineno, line in enumerate(conf_lines):
            entry = self._handler(line, lineno, self.syspaths)
            self._lines.append(entry)
            self._linemap[lineno] = entry

    @property
    def entries(self):
        """List of entries in the file.

        Expose list of entries in the conf file as a readonly attr,
        dynamically loading the file lines if necessary.
        """
        if not self._lines:
            self._load_file()

        return tuple(self._lines)

    @property
    def lines(self):
        """Expose text lines of conf file as readonly attr."""
        return tuple(str(e) for e in self.entries)

    @property
    def content(self):
        """Expose text content of conf file as readonly attr."""
        return "".join(self.lines)

    @property
    def ondisk_digest(self):
        """Generate hashed digest of on-disk file content.

        Returns hashed digest based upon on-disk file content for
        current file name; used in determining whether file has
        been modified.
        """
        with open(self.rename_phase_src) as f:
            return hasher(f.read()).hexdigest()

    @property
    def incore_digest(self):
        """Generate hashed digest of in-code file content.

        Returns hashed digest based upon in-core file content for
        conf file; used in determining whether file has been modified.
        """
        return hasher(self.content).hexdigest()

    @property
    def consistent(self):
        """True if in-core and on-disk content digests match."""
        return self.incore_digest == self.ondisk_digest

    def _update_ondisk(self):
        """Write out in-core file content to disk."""
        with open(self.orig_path, "w") as f:
            f.write(self.content)

    @property
    def dirty(self):
        """True if in-core and on-disk content differs."""
        return not self.consistent

    def replace(self, replacer):
        """Replace specific values based upon lookup table.

        Update file content via the provided DictReplacer instance,
        which will replace matching values based upon their current
        value, looked up in the replacer's lookup table.
        """
        for e in self.entries:
            e.update(replacer.replace(str(e)))

    def _rename_ondisk(self):
        """Perform an on-disk rename action.

        Perform the next on-disk rename of this conf file, if one is
        pending.
        """
        if not self.has_moved or not self.renames_remaining:
            return

        try:
            os.rename(self.rename_phase_src, self.rename_phase_dst)
        except Exception:
            sys.stderr.write("Failed to renamed '%s' to '%s'\n" %
                             (self.rename_phase_src,
                              self.rename_phase_dst))
            raise

        self._rename_phase += 1

    def commit(self, phases=1):
        """Commit pending changes for this conf file.

        Write any required changes to the conf file if it is dirty, and
        perform specified number of rename phases, where -1 means all
        remaining phases. The latter special value should only be used
        if we are certain that we are not trying to swap the names of
        two conf files.
        """
        if self.dirty:
            self._update_ondisk()

        if self.has_moved and self.renames_remaining:
            if phases == -1:
                phases = self.renames_remaining
            for phase in range(phases):
                self._rename_ondisk()


class UdevNetRulesFile(ConfFile):
    """Manage a udev net rules file.

    Provides common framework for managing net rules files.
    """

    def __init__(self, conf_file, syspaths):
        """Manage this conf file using the UdevNetEntry handler."""
        super(UdevNetRulesFile, self).__init__(conf_file, syspaths,
                                               UdevNetEntry)

    @property
    def rules(self):
        """Expose list of rules as readonly attr."""
        return tuple(e for e in self.entries if e.is_rule)

    @property
    def reordered_rules(self):
        """Expose list of re-ordered rules as readonly attr."""
        return tuple(r for r in self.rules if r.reordered)

    @property
    def reordered(self):
        """True if any rules have been re-ordered."""
        return bool(self.reordered_rules)

    @property
    def devices_exist(self):
        """Check that all rule network devices exist.

        Returns true only if all the /sys/class/net devices associated
        with all rules still exist.
        """
        return all(r.sys_path_exists for r in self.rules)


class UdevNetRulesFile70(UdevNetRulesFile):
    """Manage a udev 70-persistent-net.rules file.

    This class manages the contents of the udev persistent net
    rules file /etc/udev/rules.d/70-persistent-net.rules.
    """

    def __init__(self, syspaths):
        """Manage this conf file using the UdevNetEntry handler."""
        super(UdevNetRulesFile70, self).__init__(syspaths.rules_file_70,
                                                 syspaths)

    def reorder_rules(self):
        """Re-order the device names in the rules by PCI device.

        Sort rule devices according to the associated pci_order value,
        and rename device names based upon that ordering.
        """
        new_order = sorted(self.rules, key=attrgetter("pci_order"))
        for idx, r in enumerate(new_order):
            r.dev_rename("%s%s" % (r.dev_name_prefix, idx))


class UdevNetRulesFile71(UdevNetRulesFile):
    """Manage a udev 71-persistent-net.rules file.

    This class manages the contents of the udev persistent net
    rules file /etc/udev/rules.d/71-persistent-net.rules.
    """

    def __init__(self, syspaths):
        """Manage this conf file using the UdevNetEntry handler."""
        super(UdevNetRulesFile71, self).__init__(syspaths.rules_file_71,
                                                 syspaths)

    def reorder_rules(self):
        raise NetRulesError("Re-ordering not supported for "
                            "71-persistent-net.rules file.")


class UdevNetRulesManager(object):
    """Udev Net Rules Manager

    Class used to make the udev persistent net rules settings
    for a system. Generates a 71-persistent-net.rules file that
    orders network devices by PCI order, superceding any existing
    70-persistent-net.rules file.

    We will also update the 70-persistent-net.rules file to match
    the new order.
    """

    def __init__(self, syspaths):
        """Initialise instance settings.

        The syspaths object manages access to the system paths
        against which the operations should be performed.
        """
        self._syspaths = syspaths
        self._rules_70 = None
        self._rules_71 = None
        self._rules_71_created = False

    @property
    def syspaths(self):
        return self._syspaths

    @property
    def rules_70(self):
        if not self._rules_70:
            self._load_rules_70()

        return self._rules_70

    @property
    def rules_71(self):
        if not self._rules_71:
            self._load_rules_71()

        return self._rules_71

    @property
    def rules_71_created(self):
        return self._rules_71_created

    @property
    def rules_file_70_exists(self):
        return os.path.exists(self._syspaths.rules_file_70)

    @property
    def rules_file_71_exists(self):
        return os.path.exists(self._syspaths.rules_file_71)

    def _load_rules_70(self):
        if not self.rules_file_70_exists:
            return

        self._rules_70 = UdevNetRulesFile70(self.syspaths)

    def _load_rules_71(self):
        if not self.rules_file_71_exists:
            self._gen_rules_file_71()

        self._rules_71 = UdevNetRulesFile71(self.syspaths)

    @staticmethod
    def _get_net_dev_info(net_dev_path):
        dev_name = os.path.basename(net_dev_path)
        pci = os.path.realpath(net_dev_path).split('/')[-3]
        with file(os.path.join(net_dev_path, 'dev_port')) as fp:
            port = fp.read().strip('\0').strip()
        with file(os.path.join(net_dev_path, 'address')) as fp:
            address = fp.read().strip('\0').strip()
        return dict(dev_name=dev_name, pci=pci, port=port, address=address)

    @property
    def system_eth_devices(self):
        class_net = self.syspaths.system_sys_path('class', 'net')
        eth_dev_info = list(self._get_net_dev_info(e)
                            for e in glob(os.path.join(class_net, 'eth*')))
        return {e['dev_name']: e for e in eth_dev_info}

    @property
    def ordered_eth_devices(self):
        sys_devs = self.system_eth_devices

        pci_ordered = sorted(sys_devs.values(),
                             key=lambda x: '%s:%s' % (x['pci'], x['port']))
        ordered_devs = OrderedDict()
        for i, e in enumerate(pci_ordered):
            dev_name = 'eth%d' % i
            new_e = e.copy()
            new_e.update(dict(dev_name=dev_name))
            ordered_devs[dev_name] = new_e
        return ordered_devs

    @property
    def reordered(self):
        sys_devs = self.system_eth_devices
        ordered_devs = self.ordered_eth_devices
        return (sys_devs != ordered_devs)

    @property
    def reordered_devices(self):
        sys_devs = self.system_eth_devices
        sys_set = set("%s:%s#%s" % (e['pci'], e['port'], e['dev_name'])
                      for e in sys_devs.itervalues())

        ordered_devs = self.ordered_eth_devices
        ordered_set = set("%s:%s#%s" % (e['pci'], e['port'], e['dev_name'])
                          for e in ordered_devs.itervalues())

        set_diffs = sys_set.symmetric_difference(ordered_set)
        diff_map = {}
        for d in set_diffs:
            d_pci, d_name = d.split('#')
            if d_pci not in diff_map:
                diff_map[d_pci] = {}
            if d in sys_set:
                diff_map[d_pci]['from'] = d_name
            else:
                diff_map[d_pci]['to'] = d_name

        return sorted(diff_map.itervalues(), key=itemgetter('from'))

    @staticmethod
    def _gen_rules_71_entry(e):
        return ['',
                ('SUBSYSTEM=="net", ACTION=="add", DEVPATH=="*/%s/*", '
                 'ATTR{dev_port}=="%s", NAME="%s"' % (e['pci'], e['port'],
                                                      e['dev_name']))]

    def _gen_rules_file_71(self):
        ordered_devs = self.ordered_eth_devices
        content = ["# ARDANA-MANAGED - Managed by Ardana - Do not edit",
                   "# Generated by update_fcoe_udev during install/setup",
                   "#",
                   ("# udev rules to persistently map physical PCI devices "
                    "to ethX device names."),
                   ("# This is used to hard-wire specific ethX names to a "
                    "specific (PCI address,"),
                   ("# dev_port) pairings so that the names don't change "
                    "across reboots.")]

        for e in ordered_devs:
            content.extend(self._gen_rules_71_entry(ordered_devs[e]))

        rules_file = self.syspaths.rules_file_71
        with file(rules_file, "w") as fp:
            fp.write("\n".join(content))

        self._rules_71_created = True

    @property
    def dirty(self):
        if self.rules_71_created and self.reordered:
            return True

        if self.rules_70:
            if self.rules_70.dirty:
                return True

        return False

    @property
    def devices_exist(self):
        if not self.rules_71.devices_exist:
            return False

        if self.rules_71:
            if not self.rules_71.devices_exist:
                return False

        return True

    def reorder_rules(self):
        if self.rules_70:
            self.rules_70.reorder_rules()
        # We should never need to re-order the entries in rules_71

    def commit(self):
        if self.rules_70:
            self.rules_70.commit()


class NetworkDeviceManager(object):
    """Network Device Management Helper

    Class used to manage updating system configuration files as a
    result of reordering network devices in PCI device order.
    """

    def __init__(self, prefix, sys_prefix, syspaths=None):
        """Initialise instance settings.

        The arguments that we support are:
          * prefix - path
            The path under which to look for network configuration files.
          * sys_prefix - path
            The path under which to perform /sys lookups
        """
        if syspaths is None:
            syspaths = ArdanaSystemPaths(prefix, sys_prefix)

        self._syspaths = syspaths
        self._udev = UdevNetRulesManager(syspaths)
        self._fcoe_confs = []
        self._ifaces_confs = []
        self._remap_renamer = None

    @property
    def syspaths(self):
        """Expose syspaths as a readonly attr."""
        return self._syspaths

    @property
    def udev(self):
        """Expose udev as a readonly attr."""
        return self._udev

    @property
    def fcoe_confs(self):
        """Expose fcoe_confs as a readonly attr."""
        return tuple(self._fcoe_confs)

    @property
    def ifaces_confs(self):
        """Expose ifaces_confs as a readonly attr."""
        return tuple(self._ifaces_confs)

    @property
    def remap_renamer(self):
        """Renamer tool used to manage content updates.

        Dynamically creates a DictReplacer instance to be used for
        updating config files the first this is called after devices have
        been reordered, and thereafter returns that DictReplacer instance.
        """
        if self._remap_renamer is None and self.udev.reordered:
            # Construct a DictReplacer instance that can be used to
            # rename the device names within config files.
            reordered = self.udev.reordered_devices
            rename_map = dict(((r['from'], r['to'])
                               for r in reordered))
            self._remap_renamer = DictReplacer(r"(eth\d+)",
                                               rename_map)

        return self._remap_renamer

    _noreorder_flag = "fcoe_noreorder"

    @property
    def dont_run(self):
        """Returns true if flag found in /proc/cmdline."""
        cmdline_file = "/proc/cmdline"
        try:
            with open(cmdline_file) as f:
                cmdline = f.read()
        except Exception:
            sys.stderr.write("Failed to open '%s': %s\n" %
                             (cmdline_file, sys.exc_info()[1]))
            raise

        return self._noreorder_flag in cmdline

    @property
    def system_valid(self):
        """Check that system state is consistent and valid.

        Returns false if any of the network devices identified in
        ther persistent udev net rules doesn't exist.
        """
        return self.udev.devices_exist

    @property
    def already_processed(self):
        """Check if a system has already been processed.

        Should be called before doing anything to check if system
        has already been processed, and or needs a reboot.
        """
        # If the flag file has been created by a previous run
        # or if any of the rules have already been re-ordered
        # then we shouldn't make any more changes and instead
        # the system needs to be rebooted.
        return self.syspaths.flag_exists

    @property
    def needs_reboot(self):
        return self.udev.reordered

    def reorder_udev_rules(self):
        """Re-order network devcies in Udev persistent rules."""
        self.udev.reorder_rules()

    @property
    def fcoe_dirty(self):
        """True if any FCOE config changes pending."""
        return any(c.dirty or c.renames_remaining for c in self.fcoe_confs)

    @property
    def ifaces_dirty(self):
        """True if any network interface config changes pending."""
        return any(c.dirty or c.renames_remaining for c in self.ifaces_confs)

    @property
    def dirty(self):
        """True if any udev, FCOE or network config changes pending."""
        return self.udev.dirty or self.fcoe_dirty or self.ifaces_dirty

    def _process_candidate_conf_files(self, reordered_files):
        """Process specified conf files.

        Given a list of (rule, file) pairs, weed out those for which
        the conf file doesn't exist and then process the remaining
        conf files, updating their content as appropriate and then
        rename them in a 2 phase process; this allows us to safely
        swap files. Return the resulting list of ConfFile instances.
        """
        confs = []
        for r, f in reordered_files:
            if not os.path.exists(f):
                continue

            conf = ConfFile(f, self.syspaths)
            conf.replace(self.remap_renamer)
            temp_name = "%s...%s" % (r['from'], r['to'])
            conf.path = conf.path.replace(r['from'], temp_name)
            conf.path = conf.path.replace(temp_name, r['to'])
            confs.append(conf)

        return confs

    def update_fcoe_configs(self):
        """Update FCOE config based on re-ordered udev rules."""
        # Nothing to be done if no reordering has occurred.
        reordered = self.udev.reordered_devices
        if not reordered:
            return

        # Skip if we have already completed this stage
        if self.fcoe_confs:
            return

        # Generate candidate list of fcoe conf files, with
        # associated rule, that need to be processed
        reordered_files = tuple((r, os.path.join(self.syspaths.fcoe_dir,
                                                 "cfg-%s" % r['from']))
                                for r in reordered)

        # At this stage changes have been prepared but are not yet
        # committed to disk
        self._fcoe_confs = self._process_candidate_conf_files(reordered_files)

    def update_ifaces_configs(self):
        """Update network config based on re-ordered udev rules."""
        # Nothing to be done if no reordering has occurred.
        reordered = self.udev.reordered_devices
        if not reordered:
            return

        # Skip if we have already completed this stage
        if self.ifaces_confs:
            return

        # Generate candidate list of iface conf files, with
        # associated rule, that need to be processed.
        reordered_files = tuple((r, os.path.join(self.syspaths.ifaces_dir,
                                                 r['from']))
                                for r in reordered)

        ifaces_confs = self._process_candidate_conf_files(reordered_files)

        # Process the main interfaces file, and if it was modified, then
        # include it in the list of interface conf objects to be tracked
        conf = ConfFile(self.syspaths.ifaces_file, self.syspaths)
        conf.replace(self.remap_renamer)
        if conf.dirty:
            ifaces_confs.append(conf)

        # At this stage changes have been prepared but are not yet
        # committed to disk
        self._ifaces_confs = ifaces_confs

    @staticmethod
    def _gen_conf_changes_text(action, title, conf_list):
        """Generate change info text."""
        if not (conf_list and
                any(c.dirty or c.has_moved for c in conf_list)):
            return ""

        lines = ["%s %s Changes:" % (action, title)]

        if any(c.has_moved for c in conf_list):
            lines.append("  Reordering:")
            lines.extend(["    %s ==> %s" % (c.orig_path, c.path)
                          for c in conf_list if c.has_moved])
        if any(c.dirty for c in conf_list):
            lines.append("  Modifying:")
            lines.extend(["    %s" % c.path
                          for c in conf_list if c.has_moved])
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _gen_udev_changes_text(action, reordered_list):
        """Generate device reorder change text."""
        if not reordered_list:
            return ""

        lines = ["%s Device Re-ordering:" % action]
        lines.extend(["  %6s ==> %s" % (r['from'], r['to'])
                      for r in reordered_list])
        lines.append("")

        return "\n".join(lines)

    def _gen_changes_text(self, action):
        reordered = self.udev.reordered_devices
        changes = [self._gen_udev_changes_text(action, reordered),
                   self._gen_conf_changes_text(action, "FCOE",
                                               self.fcoe_confs),
                   self._gen_conf_changes_text(action, "Network",
                                               self.ifaces_confs)]

        return "\n".join(c for c in changes if c)

    def _create_flag_file(self, content):
        """Create flag file with provided content."""
        if not os.path.exists(self.syspaths.flag_dir):
            try:
                os.makedirs(self.syspaths.flag_dir)
            except Exception:
                sys.stderr.write("Failed to create flag directory '%s': %s\n" %
                                 (self.syspaths.flag_dir, sys.exc_info()[1]))
                raise

        try:
            with open(self.syspaths.flag_file, "w") as f:
                f.write(content)
        except Exception:
            sys.stderr.write("Failed to create flag file '%s': %s\n" %
                             (self.syspaths.flag_file, sys.exc_info()[1]))
            raise

    def commit(self):
        """Commit any pending changes to disk."""
        changes = "No reordering required."
        msg = "No device reordering required on this system."

        if self.dirty:
            print(self._gen_changes_text("Proposed"))

            # Generate committed changes text before committing.
            changes = self._gen_changes_text("Committed")

            # If the rules have been updated commit those changes
            if self.udev.dirty:
                self.udev.commit()

            # If any of the fcoe or interfaces files have been
            # updated or renamed then commit those changes
            if self.fcoe_dirty or self.ifaces_dirty:
                conf_list = self.fcoe_confs + self.ifaces_confs
                rename_phases = max(c.renames_remaining
                                    for c in conf_list)

                # We want to iterate at least once, and up to max
                # number of rename operations outstanding.
                for i in range(max(1, rename_phases)):
                    for conf in conf_list:
                        # First time through will update file content, and
                        # peforms first rename if any; subsequent commits
                        # perform any remaining renames
                        conf.commit()

            msg = ("All device reordering changes committed to disk.\n"
                   "NOTE:\n"
                   "  Please ensure that the ramdisk is updated and the\n"
                   "  system is rebooted for these changes to take effect.")

        self._create_flag_file(changes)
        print(msg)

    def process_system(self):
        """Process the current system.

        Update the system by re-ordering the udev persistent network
        rules according to PCI device order, and then reflect those
        reordering changes in the system FCOE and network interfaces
        configurations, and then commit those changes to disk.
        """
        if self.already_processed or self.dont_run or not self.system_valid:
            return

        self.reorder_udev_rules()
        self.update_fcoe_configs()
        self.update_ifaces_configs()

        self.commit()


def main():
    """Main body for script."""
    parser = ArgumentParser(description="Update FCOE device udev persisted "
                                        "ordering.")
    parser.add_argument("--prefix", "-p", default="/target",
                        help="System files will be accessed under this "
                             "prefix")
    parser.add_argument("--sys-prefix", "-s", default="/",
                        help="The /sys file system files will be accessed "
                             "under this prefix")
    args = parser.parse_args()
    NetworkDeviceManager(args.prefix, args.sys_prefix).process_system()


if __name__ == '__main__':
    main()
