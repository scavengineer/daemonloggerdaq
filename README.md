# daemonloggerdaq
Daemonlogger modified to use DAQ, primarily for listening on multiple
interfaces plus other features I thought it should have.  Sorry Marty.


DaemonLogger: Simple packet logging & soft tap daemon.
Version 1.2.1

Copyright (C) 2006-2008 Sourcefire Inc.
Author: Martin Roesch <roesch@sourcefire.com>
2016-12-15 tom currie <pepperjack@autoshun.org>
* removed pcap stuff and added daq stuff
2010-03-04 tom currie <pepperjack@autoshun.org>
* added toggle file option

This was originally a libpcap-based program, it now uses daq.  It has two 
runtime modes:

1) It sniffs packets and spools them straight to the disk and can daemonize 
itself for background packet logging.  By default the file rolls over when 
1 GB of data is logged.

2) It sniffs packets and rewrites them to a second interface, essentially 
acting as a soft tap.  It can also do this in daemon mode.

These two runtime modes are mutually exclusive, if the program is placed in
tap mode (using the -o switch) then logging to disk is disabled.

License:

GPL v2.  Make SURE you read the included COPYING file so that you understand 
how this file is licensed by Sourcefire, even though it's under the GPL v2 
there are some clarifications that we have made regarding the licensing of 
this program.

Requirements:

* A recent version of libpcap.
* A recent version of libdnet.
* A recent version of libdaq.

Usage:

daemonlogger [switches] [bpf filter]

Switches:

    -c <count>      Capture <count> packets and exit.
    -d              Daemonize at startup.
    -D <daq path>   The location on disk where we will find daq_afpacket.so
    -f <bpf file>   Load BPF filter from <bpf file>.
    -F              Make disk output "packet-buffered".  As  each packet
                    is saved, it will be written to the output file rather 
                    than being written only when the output buffer fills.
    -g <group name> Set group ID to <group name>.
    -h              Print usage message.
    -i <interface>  Sniff packets from <interface>. Supports a colon separated
                    list of interfaces: "eno1:eno3"
    -l <path>       Specify a <path> to write the pcap logfiles into.
    -m <count>      Write <count> log files and exit.  If using Ringbufer mode
                    then write <count> files and delete the oldest file in the
                    set when you exceed <count> log files written.  The 
                    program will not exit when in this mode.
    -M <pct>        Used in concert with the -r ringbuffer switch this option
                    will write log files to the disk until it is at <pct>
                    utilization and then roll over and delete the oldest log
                    file.  For example, "-M 90" would write files to the disk
                    until it is 90% utilized and then roll over and delete the      
                    oldest file in the logging directory.  If the -s "size"
                    switch is not set then the default log file size is 2GB.
    -n <name>       Set output filename prefix to <name>.  Default is
                    "daemonlogger.pcap".
    -o <outf>       Disable packet logging and write packets received on 
                    <interface> on <outf>.  Activates tap mode.
                    Example: daemonlogger -i en0 -o gre0
    -p <pidfile>    Set an explicit <pidfile> filename.  Default is 
                    daemonlogger.pid.
    -P <pidpath>    Set an explicit <pidpath> directory.  Default is /var/run.
    -r              Activate ringbuffer mode.
    -s <size>       Rollover the log file if it reaches <size> bytes.
    -S <snaplen>    Set the number of bytes to grab per packet to <snaplen>.
    -t <time>       Rollover the log file on time intervals.  Append an 'm' to
                    rollover on minute boundaries, 'h' to rollover on hour
                    boundaries and 'd' to rollover on day boundaries.  If no 
                    interval selector is used then the default rollover 
                    interval is in seconds.
                    For example, "-t 60" rolls the log file over every 60 
                    seconds and "-t 2h" rolls the log file over every two
                    hours at the top of the hour.  In the case of 
                    minute/hour/day-based rollovers, the will round to the 
                    next highest hour.  For example, if the program is told to 
                    rollover every 2 hours and is started 38 minutes into the 
                    current hour it will add 2 to the current hour and 
                    rollover as scheduled at the top of the hour at <current
                    hour> + 2.  If the program was started at 13:38 it would
                    roll over the logfile at 15:00.
    -T <chroot>     Chroot directory to <chroot>.
    -u <user name>  Set user ID to <user name>.
    -v              Show daemonlogger version.
    -X              Toggle between two files. One file will have the suffix "A"
                    the other will have the suffix "B".  Partnered with the 
                    "-m 3" will create a rolling history of all packets of the
                    previous 3-6 minutes.  This controls disk consumption which
                    allows the output files to use " -l /dev/shm ", writing
                    packet files at the speed of memory.
    -z              Select log file pruning behavior.  Omitting this switch 
                    results in the default mode being used where the oldest log
                    file in the logging directory is pruned.  Setting the -z
                    switch changes the behavior so that Daemonlogger will prune
                    the oldest file from its current instantiation and leave
                    files from older runs in the same logging directory alone.

BPF Filter:
    You can specify BPF filter commands after the command line switches just 
like in tcpdump or Snort.

This code is largely untested and probably completely shoddy.  YMMV.  Write me 
if you find bugs or want features!
