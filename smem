#!/usr/bin/env python3
#
# smem - a tool for meaningful memory reporting
#
# Copyright 2008-2009 Matt Mackall <mpm@selenic.com>
#
# This software may be used and distributed according to the terms of
# the GNU General Public License version 2 or later, incorporated
# herein by reference.

from __future__ import print_function

import argparse
import errno
import functools
import os
import pwd
import re
import sys
from multiprocessing import Pool, cpu_count
from typing import Dict, List, Optional, Sized, Union


class UIDCache(object):
    """Class for a simple ID Cache"""

    def __init__(self) -> None:
        self._cache = {}

    def __call__(self, uid):
        """Return if the entry is in cache, else populate the cache"""
        return self._cache.setdefault(uid, self._getpwuid(uid))

    @staticmethod
    def _getpwuid(uid: int) -> Union[int, str]:
        """Return the password database entry for the UID otherwise store just the UID"""
        try:
            return pwd.getpwuid(uid)[0]
        except KeyError:
            return str(uid)


class Proc(object):
    """Helper class to handle /proc/ filesystem data"""

    def __init__(self) -> None:
        pass

    @staticmethod
    def listdir() -> List[str]:
        return os.listdir("/proc")

    @staticmethod
    def read(filename) -> str:
        """Return the file as a string"""
        return open("/proc/" + filename).read()

    def readlines(self, filename):
        """Return the file as an list of lines"""
        return self.read(filename).splitlines(True)

    def version(self):
        """Return Linux version data"""
        return self.readlines("version")[0]


class MemData(Proc):
    """Class accessing and storing /proc/meminfo data"""

    def __init__(self) -> None:
        super().__init__()
        self._memdata = {}

        regex = re.compile("(?P<name>\\S+):\\s+(?P<amount>\\d+) kB")
        for line in self.readlines("meminfo"):
            match = regex.match(line)
            if match:
                self._memdata[match.group("name").lower()] = int(match.group("amount"))

    def __call__(self, entry):
        """Return the entry when the object is called"""
        return self._memdata[entry]


class ProcessData(Proc):
    """Helper class to handle /proc/<pid> filesystem data"""

    def __init__(self) -> None:
        super().__init__()
        self._uidcache = UIDCache()

    def _iskernel(self, pid):
        """Check if it's a kernel pid"""
        return self.pidcmd(pid) == ""

    @staticmethod
    def _stat(pid) -> os.stat_result:
        """Stat result for the pid"""
        return os.stat("/proc/" + pid)

    def pids(self) -> List[int]:
        """Get a list of PID's"""
        return [
            int(e)
            for e in self.listdir()
            if e.isdigit()
            and not self._iskernel(e)
            and ((options.pid and options.pid == int(e)) or not options.pid)
        ]

    def mapdata(self, pid):
        """Return PID smaps data"""
        return self.readlines("%s/smaps" % pid)

    def pidcmd(self, pid):
        """Return PID cmdline data"""
        try:
            c = self.read("%s/cmdline" % pid)[:-1]
            return c.replace("\0", " ")
        except:
            return "?"

    def piduser(self, pid):
        """Return PID user data"""
        try:
            return self._stat("%d" % pid).st_uid
        except:
            return -1

    def username(self, uid):
        """Return username from UID cache"""
        return "?" if uid == -1 else self._uidcache(uid)

    def pidusername(self, pid):
        """Return PID username"""
        return self.username(self.piduser(pid))


def totalmem():
    if options.realmem:
        return fromunits(options.realmem) / 1024
    else:
        memdata = MemData()
        return memdata("memtotal")


def pidmaps(pid) -> Dict[int, Dict[str, int]]:
    maps = {}
    start = None
    seen = False
    empty = True
    warned = False
    try:
        mapdata = proc.mapdata(pid)
    except:
        return {}

    for l in mapdata:
        empty = False
        f = l.split()
        if f[-1] == "kB":
            if f[0].startswith("Pss"):
                seen = True
            maps[start][f[0][:-1].lower()] = int(f[1])
        elif "-" in f[0] and ":" not in f[0]:  # looks like a mapping range
            start, end = f[0].split("-")
            start = int(start, 16)
            name = "<anonymous>"
            if len(f) > 5:
                name = f[5]
            maps[start] = dict(
                end=int(end, 16),
                mode=f[1],
                offset=int(f[2], 16),
                device=f[3],
                inode=f[4],
                name=name,
            )

    if not empty and not seen and not warned:
        print("Warning: Kernel does not appear to support PSS measurement")
        warned = True
        if not options.sort:
            options.sort = "rss"

    if options.mapfilter:
        f = {}
        for m in maps:
            if not filters(options.mapfilter, m, lambda x: maps[x]["name"]):
                f[m] = maps[m]
        return f
    return maps


def maptotals(pids):
    filtered_pids = filter(lambda pid: not filters(options.processfilter, pid, proc.pidcmd) and
                                       not filters(options.userfilter, pid, proc.pidusername),
                           pids)

    totals = {}
    with Pool(processes=cpu_count()) as pool:
        for maps in pool.map(pidmaps, filtered_pids):
            if len(maps) == 0:
                continue
            seen = {}
            for m in list(maps.keys()):
                name = maps[m]["name"]
                if name not in totals:
                    t = dict(
                        size=0,
                        rss=0,
                        pss=0,
                        shared_clean=0,
                        shared_dirty=0,
                        private_clean=0,
                        count=0,
                        private_dirty=0,
                        referenced=0,
                        swap=0,
                        pids=0,
                    )
                else:
                    t = totals[name]

                for k in t:
                    t[k] += maps[m].get(k, 0)
                t["count"] += 1
                if name not in seen:
                    t["pids"] += 1
                    seen[name] = 1
                totals[name] = t

    return totals


def pidmaps_rollup(pid) -> Dict[int, Dict[str, int]]:
    try:
        smaps_rollup_lines = open("/proc/%s/smaps_rollup" % pid).read().splitlines(True)
    except:
        return {}
    header = smaps_rollup_lines[0]
    stats = smaps_rollup_lines[1:]
    maps = {}

    header_parts = header.split()
    start, end = header_parts[0].split("-")
    start = int(start, 16)
    name = header_parts[5] if len(header_parts) > 5 else "<rollup>"
    maps[start] = dict(
        end=int(end, 16),
        mode=header_parts[1],
        offset=int(header_parts[2], 16),
        device=header_parts[3],
        inode=header_parts[4],
        name=name,
    )

    for stat in stats:
        key = stat[0:16].rstrip(': ')
        value = stat[17:-3].strip()
        maps[start][key.lower()] = int(value)

    return maps


def pidtotals(pid, pidmaps_f=pidmaps) -> Dict[str, int]:
    maps = pidmaps_f(pid)
    if len(maps) == 0:
        return dict(pid=pid, maps=0)

    t = dict(
        pid=pid,
        size=0,
        rss=0,
        pss=0,
        shared_clean=0,
        shared_dirty=0,
        private_clean=0,
        private_dirty=0,
        referenced=0,
        swap=0,
    )
    for m in list(maps.keys()):
        for k in t:
            t[k] += maps[m].get(k, 0)

    t["uss"] = t["private_clean"] + t["private_dirty"]
    t["maps"] = len(maps)

    return t


def usertotals(pids, pidmaps_f=pidmaps):
    filtered_pids = list(filter(lambda p: not filters(options.processfilter, p, proc.pidcmd) and
                                          not filters(options.userfilter, p, proc.pidusername),
                                pids))

    totals = {}
    with Pool(processes=cpu_count()) as pool:
        all_maps = pool.map(pidmaps_f, filtered_pids)
        for i in range(len(all_maps)):
            maps = all_maps[i]
            pid = filtered_pids[i]
            if len(maps) == 0:
                continue
            user = proc.piduser(pid)

            if user not in totals:
                t = dict(
                    size=0,
                    rss=0,
                    pss=0,
                    shared_clean=0,
                    shared_dirty=0,
                    private_clean=0,
                    count=0,
                    private_dirty=0,
                    referenced=0,
                    swap=0,
                )
            else:
                t = totals[user]

            for m in list(maps.keys()):
                for k in t:
                    t[k] += maps[m].get(k, 0)

            t["count"] += 1
            totals[user] = t

    return totals


def sortmaps(totals, key):
    l = []
    for pid in totals:
        l.append((totals[pid][key], pid))
    l.sort()
    return [pid for pid, key in l]


def units(x) -> str:
    s = ""
    if x == 0:
        return "0"
    for s in ("", "K", "M", "G", "T"):
        if x < 1024:
            break
        x /= 1024.0
    return "%.1f%s" % (x, s)


def fromunits(x) -> Optional[int]:
    s = dict(
        k=2**10,
        K=2**10,
        kB=2**10,
        KB=2**10,
        M=2**20,
        MB=2**20,
        G=2**30,
        GB=2**30,
        T=2**40,
        TB=2**40,
    )
    for k, v in list(s.items()):
        if x.endswith(k):
            return int(float(x[: -len(k)]) * v)
    sys.stderr.write("Memory size should be written with units, for example 1024M\n")
    sys.exit(-1)


def showamount(a, total: float):
    if options.abbreviate:
        return units(a * 1024)
    elif options.percent:
        if total == 0:
            return "N/A"
        return "%.2f%%" % (100.0 * a / total)
    return a


def filters(opt, arg, *sources) -> bool:
    if not opt:
        return False

    for f in sources:
        if re.search(opt, f(arg)):
            return False
    return True


def processtotals(pids, pidmaps_f=pidmaps):
    filtered_pids = filter(lambda pid: not filters(options.processfilter, pid, proc.pidcmd) and
                                       not filters(options.userfilter, pid, proc.pidusername),
                           pids)
    totals = {}
    with Pool(processes=cpu_count()) as pool:
        for p in pool.map(functools.partial(pidtotals, pidmaps_f=pidmaps_f), filtered_pids):
            if p["maps"] != 0:
                totals[p["pid"]] = p

    return totals


def widthstr(field, width, default) -> str:
    if width == 0:
        return "%s"
    if width < 0:
        size = default
    else:
        size = width
        ignore_autosize.add(field)
    return "%-{size}.{size}s".format(size=size)


def showpids(pidmaps_f=pidmaps) -> None:
    p = proc.pids()
    pt = processtotals(p, pidmaps_f)

    def showuser(p):
        if options.numeric:
            return proc.piduser(p)
        return proc.pidusername(p)

    fields = dict(
        pid=("PID", lambda n: n, "% 6s", lambda x: len(pt), "process ID"),
        user=(
            "User",
            showuser,
            widthstr("user", options.user_width, 8),
            lambda x: len(dict.fromkeys(x)),
            "owner of process",
        ),
        command=(
            "Command",
            proc.pidcmd,
            widthstr("command", options.cmd_width, 27),
            None,
            "process command line",
        ),
        maps=("Maps", lambda n: pt[n]["maps"], "% 5s", sum, "total number of mappings"),
        swap=(
            "Swap",
            lambda n: pt[n]["swap"],
            "% 8a",
            sum,
            "amount of swap space consumed (ignoring sharing)",
        ),
        uss=("USS", lambda n: pt[n]["uss"], "% 8a", sum, "unique set size"),
        rss=(
            "RSS",
            lambda n: pt[n]["rss"],
            "% 8a",
            sum,
            "resident set size (ignoring sharing)",
        ),
        pss=(
            "PSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "proportional set size (including sharing)",
        ),
        vss=(
            "VSS",
            lambda n: pt[n]["size"],
            "% 8a",
            sum,
            "virtual set size (total virtual memory mapped)",
        ),
    )
    columns = options.columns or "pid user command swap uss pss rss"

    showtable(list(pt.keys()), fields, columns.split(), options.sort or "pss")


def showmaps() -> None:
    p = proc.pids()
    pt = maptotals(p)

    fields = dict(
        map=(
            "Map",
            lambda n: n,
            widthstr("map", options.mapping_width, 40),
            len,
            "mapping name",
        ),
        count=(
            "Count",
            lambda n: pt[n]["count"],
            "% 5s",
            sum,
            "number of mappings found",
        ),
        pids=(
            "PIDs",
            lambda n: pt[n]["pids"],
            "% 5s",
            sum,
            "number of PIDs using mapping",
        ),
        swap=(
            "Swap",
            lambda n: pt[n]["swap"],
            "% 8a",
            sum,
            "amount of swap space consumed (ignoring sharing)",
        ),
        uss=(
            "USS",
            lambda n: pt[n]["private_clean"] + pt[n]["private_dirty"],
            "% 8a",
            sum,
            "unique set size",
        ),
        rss=(
            "RSS",
            lambda n: pt[n]["rss"],
            "% 8a",
            sum,
            "resident set size (ignoring sharing)",
        ),
        pss=(
            "PSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "proportional set size (including sharing)",
        ),
        vss=(
            "VSS",
            lambda n: pt[n]["size"],
            "% 8a",
            sum,
            "virtual set size (total virtual address space mapped)",
        ),
        avgpss=(
            "AVGPSS",
            lambda n: int(1.0 * pt[n]["pss"] / pt[n]["pids"]),
            "% 8a",
            sum,
            "average PSS per PID",
        ),
        avguss=(
            "AVGUSS",
            lambda n: int(
                1.0 * (pt[n]["private_clean"] + pt[n]["private_dirty"]) / pt[n]["pids"]
            ),
            "% 8a",
            sum,
            "average USS per PID",
        ),
        avgrss=(
            "AVGRSS",
            lambda n: int(1.0 * pt[n]["rss"] / pt[n]["pids"]),
            "% 8a",
            sum,
            "average RSS per PID",
        ),
    )
    columns = options.columns or "map pids avgpss pss"

    showtable(list(pt.keys()), fields, columns.split(), options.sort or "pss")


def showusers(pidmaps_f=pidmaps) -> None:

    p = proc.pids()
    pt = usertotals(p, pidmaps_f=pidmaps_f)

    def showuser(u):
        if options.numeric:
            return u
        return proc.username(u)

    fields = dict(
        user=(
            "User",
            showuser,
            widthstr("user", options.user_width, 8),
            None,
            "user name or ID",
        ),
        count=("Count", lambda n: pt[n]["count"], "% 5s", sum, "number of processes"),
        swap=(
            "Swap",
            lambda n: pt[n]["swap"],
            "% 8a",
            sum,
            "amount of swapspace consumed (ignoring sharing)",
        ),
        uss=(
            "USS",
            lambda n: pt[n]["private_clean"] + pt[n]["private_dirty"],
            "% 8a",
            sum,
            "unique set size",
        ),
        rss=(
            "RSS",
            lambda n: pt[n]["rss"],
            "% 8a",
            sum,
            "resident set size (ignoring sharing)",
        ),
        pss=(
            "PSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "proportional set size (including sharing)",
        ),
        vss=(
            "VSS",
            lambda n: pt[n]["pss"],
            "% 8a",
            sum,
            "virtual set size (total virtual memory mapped)",
        ),
    )
    columns = options.columns or "user count swap uss pss rss"

    showtable(list(pt.keys()), fields, columns.split(), options.sort or "pss")


def kernelsize() -> int:
    kernelsize = 0
    if not kernelsize and options.kernel:
        try:
            d = os.popen("size %s" % options.kernel).readlines()[1].split()
            if int(d[1]) == 0:  # data part missing, seems like packed file
                # try some heuristic to find gzipped part in kernel image
                packedkernel = open(options.kernel, "rb").read()
                pos = packedkernel.find(b"\x1F\x8B")
                if pos >= 0 and pos < 25000:
                    sys.stderr.write(
                        "Parameter '%s' should be an original uncompressed compiled kernel file.\n"
                        % options.kernel
                    )
                    sys.stderr.write(
                        "Maybe uncompressed kernel can be extracted by the command:\n"
                        "  dd if=%s bs=1 skip=%d | gzip -d >%s.unpacked\n\n"
                        % (options.kernel, pos, options.kernel)
                    )
            else:
                kernelsize = int(int(d[3]) / 1024 + 0.5)
        except:
            pass
    return kernelsize


def showsystem() -> None:
    t = totalmem()
    ki = kernelsize()
    m = MemData()

    mt = m("memtotal")
    f = m("memfree")

    # total amount used by hardware
    fh = max(t - mt - ki, 0)

    # total amount mapped into userspace (ie mapped an unmapped pages)
    u = m("anonpages") + m("mapped")

    # total amount allocated by kernel not for userspace
    kd = mt - f - u

    # total amount in kernel caches
    kdc = m("buffers") + m("sreclaimable") + (m("cached") - m("mapped"))

    l = [
        ("firmware/hardware", fh, 0),
        ("kernel image", ki, 0),
        ("kernel dynamic memory", kd, kdc),
        ("userspace memory", u, m("mapped")),
        ("free memory", f, f),
    ]

    fields = dict(
        order=("Order", lambda n: n, "% 1s", lambda x: "", "hierarchical order"),
        area=("Area", lambda n: l[n][0], "%-24s", lambda x: "", "memory area"),
        used=("Used", lambda n: l[n][1], "%10a", sum, "area in use"),
        cache=(
            "Cache",
            lambda n: l[n][2],
            "%10a",
            sum,
            "area used as reclaimable cache",
        ),
        noncache=(
            "Noncache",
            lambda n: l[n][1] - l[n][2],
            "%10a",
            sum,
            "area not reclaimable",
        ),
    )

    columns = options.columns or "area used cache noncache"
    showtable(list(range(len(l))), fields, columns.split(), options.sort or "order")


def showfields(fields, f) -> None:
    if type(f) in (list, set):
        print("unknown fields: " + " ".join(f))
    else:
        print("unknown field %s" % f)
    print("known fields:")
    for l in sorted(fields):
        print("%-8s %s" % (l, fields[l][-1]))


def autosize(columns: Sized, fields, rows):
    colsizes = {}
    for c in columns:
        if c in ignore_autosize:
            continue
        sizes = [1]

        if not options.no_header:
            sizes.append(len(fields[c][0]))

        if (options.abbreviate or options.percent) and "a" in fields[c][2]:
            sizes.append(7)
        else:
            for r in rows:
                sizes.append(len(str(fields[c][1](r))))

        colsizes[c] = max(sizes)

    overflowcols = (set(["command", "map"]) & set(columns)) - ignore_autosize
    if len(overflowcols) > 0:
        overflowcol = overflowcols.pop()
        totnoflow = sum(colsizes.values()) - colsizes[overflowcol]
        try:
            ttyrows, ttycolumns = os.popen("stty size", "r").read().split()
            ttyrows, ttycolumns = int(ttyrows), int(ttycolumns)
        except:
            ttyrows, ttycolumns = (24, 80)
        maxflowcol = ttycolumns - totnoflow - len(columns)
        maxflowcol = max(maxflowcol, 10)
        colsizes[overflowcol] = min(colsizes[overflowcol], maxflowcol)

    return colsizes


def showtable(rows, fields, columns, sort) -> None:
    header = ""
    table_format = ""
    formatter = []

    if sort not in fields:
        showfields(fields, sort)
        sys.exit(-1)

    mt = totalmem()
    memdata = MemData()
    st = memdata("swaptotal")

    missing = set(columns) - set(fields)
    if len(missing) > 0:
        showfields(fields, missing)
        sys.exit(-1)

    if options.autosize:
        colsizes = autosize(columns, fields, rows)
    else:
        colsizes = {}

    for n in columns:
        f = fields[n][2]
        if "a" in f:
            if n == "swap":
                formatter.append(lambda x: showamount(x, st))
            else:
                formatter.append(lambda x: showamount(x, mt))
            f = f.replace("a", "s")
        else:
            formatter.append(lambda x: x)
        if n in colsizes:
            f = re.sub(r"[0-9]+", str(colsizes[n]), f)
        table_format += f + " "
        header += f % fields[n][0] + " "

    l = []
    for n in rows:
        r = [fields[c][1](n) for c in columns]
        l.append((fields[sort][1](n), r))

    l.sort(reverse=bool(options.reverse))

    if not options.no_header:
        print(header)

    for k, r in l:
        print(table_format % tuple([f(v) for f, v in zip(formatter, r)]))

    if options.totals:
        # totals
        t = []
        for c in columns:
            f = fields[c][3]
            if f:
                t.append(f([fields[c][1](n) for n in rows]))
            else:
                t.append("")

        print("-" * len(header))
        print(table_format % tuple([f(v) for f, v in zip(formatter, t)]))


def parse_arguments(argv=None) -> argparse.Namespace:

    argparser = argparse.ArgumentParser(
        prog="smem",
        description="""
                    smem is a tool that can give numerous reports on memory usage on Linux systems.
                    Unlike existing tools, smem can report proportional set size (PSS), which is a
                    more meaningful representation of the amount of memory used by libraries and
                    applications in a virtual memory system.
                    """,
        epilog="""
               For more information please visit:
               https://github.com/kwkroeger/smem
               """,
    )

    argparser.add_argument(
        "-H", "--no-header", action="store_true", help="Disable header line"
    )

    argparser.add_argument(
        "-c", "--columns", default=None, type=str, help="Columns to show"
    )

    argparser.add_argument(
        "-a",
        "--autosize",
        action="store_true",
        help="Size columns to fit terminal size",
    )

    argparser.add_argument(
        "-R", "--realmem", default=None, type=str, help="Amount of physical RAM"
    )

    argparser.add_argument(
        "-K", "--kernel", default=None, type=str, help="Path to kernel image"
    )

    filter_group = argparser.add_argument_group("Filter")
    filter_group.add_argument(
        "-P", "--processfilter", default=None, type=str, help="Process filter regex"
    )

    filter_group.add_argument(
        "-M", "--mapfilter", default=None, type=str, help="Process map regex"
    )

    filter_group.add_argument(
        "-U", "--userfilter", default=None, type=str, help="Process users regex"
    )

    show_group = argparser.add_argument_group("Show")
    show_group.add_argument(
        "-m", "--mappings", action="store_true", help="Show mappings"
    )

    show_group.add_argument("-u", "--users", action="store_true", help="Show users")

    show_group.add_argument(
        "-w", "--system", action="store_true", help="Show whole system"
    )

    show_group.add_argument(
        "-p", "--percent", action="store_true", help="Show percentage"
    )

    show_group.add_argument(
        "-k", "--abbreviate", action="store_true", help="Show unit suffixes"
    )

    show_group.add_argument("-t", "--totals", action="store_true", help="Show totals")

    sort_group = argparser.add_argument_group("Sort")
    sort_group.add_argument("-n", "--numeric", action="store_true", help="Numeric sort")

    sort_group.add_argument(
        "-s", "--sort", default=None, type=str, help="Field to sort on"
    )

    sort_group.add_argument("-r", "--reverse", action="store_true", help="Reverse sort")

    width_group = argparser.add_argument_group("Width")
    width_group.add_argument(
        "--cmd-width",
        default=-1,
        type=int,
        help="Text width for commands (0=as needed)",
    )

    width_group.add_argument(
        "--name-width",
        default=-1,
        type=int,
        help="Text width for command names (0=as needed)",
    )

    width_group.add_argument(
        "--user-width",
        default=-1,
        type=int,
        help="Text width for user names (0=as needed)",
    )

    width_group.add_argument(
        "--mapping-width",
        default=-1,
        type=int,
        help="Text width for mapping names (0=as needed)",
    )

    argparser.add_argument(
        "-S", "--source", default=None, type=str, help="/proc data source"
    )

    argparser.add_argument(
        "--pid",
        default=None,
        type=int,
        help="Show just process memory based on one pid",
    )

    return argparser.parse_args()


def main() -> None:
    """Main function for smem"""

    # TODO Remove the necessity of globals, this is a temporary workaround until functions have been updated
    global ignore_autosize
    global options
    global proc

    options = parse_arguments(sys.argv)
    ignore_autosize = set()

    # Check if Linux kernel supports smaps_rollup
    pidmaps_f = pidmaps_rollup if os.access("/proc/%s/smaps_rollup" % os.getpid(), os.R_OK) else pidmaps

    proc = ProcessData()

    try:
        if options.mappings:
            showmaps()
        elif options.users:
            showusers(pidmaps_f)
        elif options.system:
            showsystem()
        else:
            showpids(pidmaps_f)
    except IOError as e:
        if e.errno == errno.EPIPE:
            pass
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
