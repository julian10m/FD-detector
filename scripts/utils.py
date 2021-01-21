#!/bin/python
import matplotlib

matplotlib.use('Agg')

import warnings

warnings.filterwarnings("ignore", message="numpy.dtype size changed")
warnings.filterwarnings("ignore", message="numpy.ufunc size changed")
warnings.filterwarnings("ignore", message="Attempting to set identical bottom==top results")
# warnings.filterwarnings("ignore", class="DeprecationWarning")

import json
import sys
import os
import glob
import radix  # leveraging radix tree is alternative to the solution based on ipaddress
# import time  # used only for performance comparison, not needed anymore.
from collections import Counter, defaultdict
import socket
import random
from itertools import groupby
from pprint import pprint
import networkx as nx  # needed for managing MDA results
import ipaddress  # needed for telling ip private addresses when ip2as mapping fails

# Graph-relatd stuff
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from cycler import cycler
from ecciddieffe import plotECDF

import sqlite3

flatten = lambda l: [item for sublist in l for item in sublist]

TIR_LABEL = 'TIR'
DIR_LABEL = 'DIR'
Q_TIRS_MIN_IE = 100

def reverseDNS(ip):
    try:
        fqdn = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        fqdn = ""
    return fqdn


class WhoisServer():

    def __init__(self, server):
        self.server = server

    def __whois(self, query):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.server, 43))
        sock.send(query + '\r\n')
        response = ''

        while True:
            d = sock.recv(4096)
            response += d
            if d == '':
                break
        sock.close()
        return response

    def __getASDescr(self, whoisDump):
        foundLine = None
        for line in whoisDump.split("\n"):
            if line.startswith("descr:"):
                foundLine = line
                break
        if foundLine:
            return foundLine.split("descr:")[1].strip()
        else:
            return ""

    def asLookup(self, asnum):
        if not asnum.startswith("AS"):
            asnum = "AS%s" % asnum
        return self.__getASDescr(self.__whois(asnum))


# IMPLEMENT IT IF NEEDED
#    def ipLookup(self, ip):
#        return self.__whois(ip)


def parseDump(filename):
    """
    Parses the dump file obtained leveraging *sc_wartsdump*.
    Returns: rawHeader, hops, source, and destination.
    Works when a single destination is probed.
    """

    rawHeader = ""
    hops = {}
    src = ""
    dst = ""

    # extract trace hops as a dictionary (hopNum --> IpAddr)
    with open(filename) as f:
        lines = f.readlines()

    rawHops = [line.strip() for line in lines if line.startswith("hop")]
    for rh in rawHops:
        _, hopNum, ipAddr = rh.split()
        hops[int(hopNum)] = ipAddr

    # extract raw header as is (as a string)
    for line in lines:
        if line.startswith("hop"):
            break
        else:
            rawHeader += line

    # extract src and destination (as strings)
    for line in lines:
        if line.startswith("traceroute"):
            myLine = line
            break
    myLineItems = myLine.split()
    src = myLineItems[myLineItems.index("from") + 1]
    dst = myLineItems[myLineItems.index("to") + 1]

    return rawHeader, hops, src, dst


def parseAnalysisDumpLine(line):
    """
    Parses the file obtanined with *sc_analysisdump -M*.
    The format can be found in the header of the dumped file and is reported below.
    """

    # There is one trace per line, with the following tab-separated fields:
    #
    #
    #  1. Key -- Indicates the type of line and determines the meaning of the
    #            remaining fields.  This will always be 'T' for an IP trace.
    #
    # -------------------- Header Fields ------------------
    #
    #  2. Source -- Source IP of skitter/scamper monitor performing the trace.
    #
    #  3. Destination -- Destination IP being traced.
    #
    #  4. ListId -- ID of the list containing this destination address.
    #
    #        This value will be zero if no list ID was provided.  (uint32_t)
    #
    #  5. CycleId -- ID of current probing cycle (a cycle is a single run
    #                through a given list).  For skitter traces, cycle IDs
    #                will be equal to or slightly earlier than the timestamp
    #                of the first trace in each cycle. There is no standard
    #                interpretation for scamper cycle IDs.
    #
    #        This value will be zero if no cycle ID was provided.  (uint32_t)
    #
    #  6. Timestamp -- Timestamp when trace began to this destination.
    #
    # -------------------- Reply Fields ------------------
    #
    #  7. DestReplied -- Whether a response from the destination was received.
    #
    #        R - Replied, reply was received
    #        N - Not-replied, no reply was received;
    #            Since skitter sends a packet with a TTL of 255 when it halts
    #            probing, it is still possible for the final destination to
    #            send a reply and for the HaltReasonData (see below) to not
    #            equal no_halt.  Note: scamper does not perform last-ditch
    #            probing at TTL 255 by default.
    #
    #  8. DestRTT -- RTT (ms) of first response packet from destination.
    #        0 if DestReplied is N.
    #
    #  9. RequestTTL -- TTL set in request packet which elicited a response
    #      (echo reply) from the destination.
    #        0 if DestReplied is N.
    #
    # 10. ReplyTTL -- TTL found in reply packet from destination;
    #        0 if DestReplied is N.
    #
    # -------------------- Halt Fields ------------------
    #
    # 11. HaltReason -- The reason, if any, why incremental probing stopped.
    #
    # 12. HaltReasonData -- Extra data about why probing halted.
    #
    #        HaltReason            HaltReasonData
    #        ------------------------------------
    #        S (success/no_halt)    0
    #        U (icmp_unreachable)   icmp_code
    #        L (loop_detected)      loop_length
    #        G (gap_detected)       gap_limit
    #
    # -------------------- Path Fields ------------------
    #
    # 13. PathComplete -- Whether all hops to destination were found.
    #
    #        C - Complete, all hops found
    #        I - Incomplete, at least one hop is missing (i.e., did not
    #            respond)
    #
    # 14. PerHopData -- Response data for the first hop.
    #
    #       If multiple IP addresses respond at the same hop, response data
    #       for each IP address are separated by semicolons:
    #
    #       IP,RTT,nTries,M|ttl|label|exp|s                                     (for only one responding IP)
    #       IP,RTT,nTries,M|ttl|label|exp|s;IP,RTT,nTries,M|ttl|label|exp|s     (for multiple responding IPs)
    #
    #         where
    #
    #       IP -- IP address which sent a TTL expired packet
    #       RTT -- RTT of the TTL expired packet
    #       nTries -- number of tries before response received from hop
    #       ttl   -- the TTL in the MPLS header
    #       label -- the label in the MPLS header
    #       exp   -- the value of the 3 Exp bits in the MPLS header
    #       s     -- the value of the 'S' bit in the MPLS header
    #
    #       This field will have the value 'q' if there was no response at
    #       this hop.
    #
    # 15. PerHopData -- Response data for the second hop in the same format
    #       as field 14.
    #
    # ...
    #

    splitLine = line.strip().split("\t")

    key = splitLine[1 - 1]
    source = splitLine[2 - 1]
    destination = splitLine[3 - 1]
    listId = splitLine[4 - 1]
    cycleId = splitLine[5 - 1]
    timestamp = splitLine[6 - 1]

    destReplied = splitLine[7 - 1]
    destRTT = splitLine[8 - 1]
    requestTTL = splitLine[9 - 1]
    reply = splitLine[10 - 1]

    haltReason = splitLine[11 - 1]
    haltReasonData = splitLine[12 - 1]
    pathComplete = splitLine[13 - 1]

    perHopData = splitLine[14 - 1:]

    return {
        "key": key,
        "source": source,
        "destination": destination,
        "listId": listId,
        "cycleId": cycleId,
        "timestamp": timestamp,
        "destReplied": destReplied,
        "destRTT": destRTT,
        "requestTTL": requestTTL,
        "reply": reply,
        "haltReason": haltReason,
        "haltReasonData": haltReasonData,
        "pathComplete": pathComplete,
        "perHopData": perHopData
    }


def parseRipeAtlasTrace(dictTrace):
    """
    Parses traces as provided by ripe atlas (json format).
    """

    d = dictTrace
    destination = d["dst_addr"]
    timestamp = d["timestamp"]
    source = d["src_addr"]

    perHopData = {x["hop"] - 1: x["result"] for x in d["result"]}

    # in case of N "*" at the end of the trace,
    # Ripe Atlas probes send a packet with TTL = 255.
    # Just discard this information.
    if 254 in perHopData:
        del perHopData[254]

    requestTTL = max(perHopData.keys()) + 1 if (
            perHopData[max(perHopData.keys())][0].has_key("from") and perHopData[max(perHopData.keys())][0][
        "from"] == destination) else 0  # in case of multipe ips per hop, only the first one is checked.
    # Should not represent a problem for the destination hop

    destReplied = "R" if requestTTL > 0 else "N"

    #    pprint(perHopData)
    #    pprint(perHopData.keys())
    #    print max(perHopData.keys())
    #    print destReplied
    #    raw_input()

    if destReplied == "R":
        destRTT = perHopData[max(perHopData.keys())][0]["rtt"]
    else:
        destRTT = 0

    if destReplied == "R":
        del perHopData[max(perHopData.keys())]

    # Fields below cannot be filled for ripe atras traces
    reply = key = listId = cycleId = haltReasonData = haltReason = None

    # Fields below can be filled but parser implementation is missing
    pathComplete = None  # TODO: path complete parser

    return {
        "key": key,
        "source": source,
        "destination": destination,
        "listId": listId,
        "cycleId": cycleId,
        "timestamp": timestamp,
        "destReplied": destReplied,
        "destRTT": destRTT,
        "requestTTL": requestTTL,
        "reply": reply,
        "haltReason": haltReason,
        "haltReasonData": haltReasonData,
        "pathComplete": pathComplete,
        "perHopData": perHopData
    }


def parsePfx2as(filename):
    """
    Parses IP2AS information base (CAIDA pfx2as format).
    Returns: the list of 3-tuples (pfx, pfxLen, AS).
    """

    with open(filename) as f:
        mappingInfoBase = []
        while True:
            line = f.readline()
            if line == "":
                break
            pfx, pfxLen, AS = line.split()
            t = (pfx, pfxLen, AS)

            mappingInfoBase.append(t)

        return mappingInfoBase


class DestinationMDACampaign:
    """
    Results of destination MDA test.

    """

    def __init__(self, mdaFolder, mapper, transitTracesCampaign=None):
        """
        :param mdaFolder: folder containing results of destination MDA (naming scheme: "<IP>_<AS>.adump")
        :param mapper: object to run IP2AS mapping
        """
        self.tracesets = defaultdict(set)  # path -> set of paths with the same cost
        self.ASOnPathDict = defaultdict(list) # (ip, AS) -> list of ASes on Path

        paths = glob.glob("{}/*.adump".format(mdaFolder))
        for path in paths:
            filename = os.path.basename(path)
            ip = filename.split(".adump")[0].split("_")[0]
            AS = filename.split(".adump")[0].split("_")[1]
            c = TraceCampaign(path)
            c.IP2ASMappingAndRelated(mapper)
            for t in c.traces:
                if AS in t.ASInfo:
                    self.ASOnPathDict[(ip, AS)].append(t.ASInfo[AS])

        for ip, AS in self.ASOnPathDict:

            subpaths = {x.subpath for x in self.ASOnPathDict[(ip, AS)]}

            # add "initial" transit path to tracesets data structure
            if transitTracesCampaign and ip in transitTracesCampaign.tracesByDestination:
                if AS in transitTracesCampaign.tracesByDestination[ip].ASInfo:
                    sub_t = transitTracesCampaign.tracesByDestination[ip].ASInfo[AS].subpath
                    subpaths.add(sub_t)

            self.updateTracesets(subpaths)  # implements the same logic used by destMDA probing.


    def returnECMPOutcome(self, sub_t, sub_d, destination, AS):
        """
        For a given transit subpath <sub_t> (obtained tracing towards <destination> and focusing on <AS>)
        compares the related direct subpath <sub_d> to subpaths having equal cost than <sub_t> (obtained with dest-mda).
        Is the direct path included in the equal-cost paths associated to the transit path?
        """

        # possible outcomes:
        OUTCOME_SAME = "SAME"
        OUTCOME_ECMP = "ECMP"
        OUTCOME_NOECMP = "NO_ECMP"
        OUTCOME_INCONCLUSIVE = "INCONCLUSIVE"
        OUTCOME_NOTPROBED = "NOT_PROBED"

        #MAXTRACES = 30
        MAXTRACES = 10

        if sub_d == sub_t:
            return OUTCOME_SAME

        elif (destination, AS) not in self.ASOnPathDict:
            return OUTCOME_NOTPROBED

        elif sub_d in self.tracesets[sub_t]:
            return OUTCOME_ECMP

        elif len(self.ASOnPathDict[(destination, AS)]) >= MAXTRACES and sub_d not in self.tracesets[sub_t]:
            return OUTCOME_INCONCLUSIVE

        else:
            return OUTCOME_NOECMP



    def updateTracesets(self, pathset):
        """
        Compares <pathset> with those in <self.tracesets>.

        Tracesets is a dictionary. path --> set of path

        There exist 3 cases:
        - pathset overlaps with no sets in tracesets
        - pathset overlaps with only one set in tracesets
        - pathset overlaps with more than one set in tracesets.
        Merges sets in self.tracesets accordingly.
        Add new keys to tracesets.
        """

        testedSets = []  # needed to avoid unneeded comparisons.
        overlapping = []  # sets overlapping with pathsets
        allsets = self.tracesets.values()

        for s in allsets:
            if s in testedSets:
                continue

            elif not s.isdisjoint(pathset):
                overlapping.append(s)
            testedSets.append(s)

        if len(overlapping) == 0:
            # no overlap.
            # add a single new set to <tracesets>, with related keys.
            for p in pathset:
                self.tracesets[p] = pathset

        elif len(overlapping) == 1:
            # overlap with a single set.
            # update existing set and assign to path in <pathset>
            overlapped = overlapping.pop()
            overlapped.update(pathset)

            for p in overlapped:
                self.tracesets[p] = overlapped

        else:  # len(overlapping) > 1:
            # overlap with multiple sets.
            # merge these sets and extend with <pathset>.
            # then assign this new set to each path.
            new = set()
            for s in overlapping:
                new.update(s)
            new.update(pathset)

            for p in new:
                self.tracesets[p] = new


class Trace:
    """
    Each object is a distinct traceroute trace.
    """
    SCAMPER_FORMAT = "SCAMPER"
    RIPEATLAS_FORMAT = "RIPE-ATLAS"

    def __init__(self, inputData, format=SCAMPER_FORMAT, originatingCampaign=None):

        self.srcFormat = format

        if originatingCampaign:
            self.originatingCampaign = originatingCampaign
        else:
            self.originatingCampaign = "UNKNOWN"

        if format == Trace.SCAMPER_FORMAT:
            self.scamperRawLine = inputData
            traceInfo = parseAnalysisDumpLine(self.scamperRawLine)  # returns a dictionary
            self.rawInput = self.scamperRawLine

        elif format == Trace.RIPEATLAS_FORMAT:
            self.ripeRawDictionary = inputData
            traceInfo = parseRipeAtlasTrace(self.ripeRawDictionary)  # returns a dictionary
            self.rawInput = self.ripeRawDictionary

        self.source = traceInfo["source"]  # IP address of the probe node
        self.destination = traceInfo["destination"]  # traceroute destination
        self.timestamp = traceInfo["timestamp"]  # unix timestamp
        self.pathComplete = traceInfo["pathComplete"]  # C=COMPLETE / I=INCOMPLETE
        self.destReplied = traceInfo["destReplied"]  # R=REPLIED / N=NOT REPLIED
        self.destDistance = int(traceInfo[
                                    "requestTTL"])  # TTL set in request packet which elicited a response (echo reply) from the destination.
        self.destRTT = float(traceInfo["destRTT"])

        # extract only IP addresses from perHopData, coming in the following format:
        # IP,RTT,nTries,M|ttl|label|exp|s                                     (for only one responding IP)
        # IP,RTT,nTries,M|ttl|label|exp|s;IP,RTT,nTries,M|ttl|label|exp|s     (for multiple responding IPs)
        # ['q', 'q', '193.206.130.5,0.916,1', '90.147.80.170,15.325,1,M|1|697539|0|1', '90.147.80.29,4.626,1,M|1|704556|0|1', '90.147.80.17,14.532,1', '72.14.214.105,14.579,1', '108.170.245.65,15.493,1', '209.85.249.123,14.725,1']
        perHopData = traceInfo["perHopData"]

        hops = {}
        hopsByTLL = []
        rttInfo = {}
        mplsInfo = {}

        if format == Trace.SCAMPER_FORMAT:

            for i in range(0, len(perHopData)):
                mplsInfo[i] = None  # initialize to None
                phd = perHopData[i]
                splitPhd = phd.split(";")  # for multiple responding IPs at the same hop
                ipAddresses = []
                rtts = []
                mplsStuff = {}
                for j in splitPhd:
                    ipAddress = j.split(",")[0]  # IP address only
                    ipAddresses.append(ipAddress)
                    try:
                        rtt = j.split(",")[1]  # rtt
                        rtt = float(rtt)
                    except IndexError, e:
                        rtt = 'q'
                    rtts.append(rtt)
                    if len(j.split(",")) == 4:  # MPLS info found

                        # Please Note: in case of multiple ips per hop, mplsInfo will contain the MPLS information related to the last ip.
                        # For the sake of completeness it should be a list, but this changes implies changes every time this field is checked.
                        # i.e.: mplsInfo == {} should become: mpldInfo == []
                        mplsStuff = {
                            "ttl": j.split(",")[3].split("|")[1],
                            "label": j.split(",")[3].split("|")[2],
                            "exp": j.split(",")[3].split("|")[3],
                            "s": j.split(",")[3].split("|")[4],
                            "ipAddress": ipAddress
                            # I know, it's redundant in most cases. I could be needed in case of multiple IPs at the same hop, if MPLS label is associated only to a subset of them
                        }

                hops[i] = ipAddresses
                hopsByTLL.append(ipAddresses)
                rttInfo[i] = rtts
                mplsInfo[i] = mplsStuff

        elif format == Trace.RIPEATLAS_FORMAT:

            for i in range(0, len(perHopData)):

                nonRespondingHop = not (True in [x.has_key("from") and x.has_key("rtt") for x in perHopData[i]])
                if nonRespondingHop:
                    ipAddresses = ['q']
                    rtts = ['q']

                else:
                    ipAddresses = [str(x["from"]) for x in perHopData[i] if (x.has_key("from") and x.has_key("rtt"))]
                    rtts = [float(x["rtt"]) for x in perHopData[i] if (x.has_key("from") and x.has_key("rtt"))]
                hops[i] = ipAddresses
                rttInfo[i] = rtts

                # Please Note: in case of multiple ips per hop, mplsInfo will contain the MPLS information related to the last ip exposing MPLS HEADER.
                # For the sake of completeness it should be a list, but this changes implies changes every time this field is checked.
                # i.e.: mplsInfo == {} should become: mpldInfo == []

                mplsStuff = {}

                for x in perHopData[i]:
                    try:
                        mplsStuff = x["icmpext"]["obj"][0]["mpls"][0]
                        mplsStuff["ipAddress"] = x["from"]  # for coherence with the SCAMPER-FORMAT CASE

                        # mplsStuff = x["icmpext"]["obj"]["mpls"]
                    except KeyError, e:
                        pass
                mplsInfo[i] = mplsStuff

        #        pprint(hops)
        #        pprint (mplsInfo)
        #        raw_input()
        #        return

        self.hops = hops  # dictionary: {hopNum --> [IP1, IP2, ...]} -
        self.hopsByTLL = hopsByTLL  # list of hops
        self.rtts = rttInfo  # dictionary: {hopNum --> [RTT1, RTT2, ...]} -

        self.mplsInfo = mplsInfo  # dictionary  {hopNum --> {mplsStuff}, hopNum --> None} - None in case of missing MPLS stuff

        self.mplsHopNum = len([x for x in self.mplsInfo if self.mplsInfo[x] != {}])

        rttsByIP = defaultdict(list)

        for i in range(0, len(self.hops)):
            ips = self.hops[i]
            rtts = self.rtts[i]

            for j in range(0, len(ips)):
                rttsByIP[ips[j]].append(rtts[j])
        self.rttsByIP = rttsByIP

        #  The attriutes below can be populated only after IP2AS mapping

        self.ASHops = {}  # AS number associated to the traced IP addresses - dictionary: {hopNum --> [AS1, AS2, ...]}
        self.egressVector = {}  # dictionary: {hopNum --> True/False}
        self.ingressVector = {}  # dictionary: {hopNum --> True/False}
        self.destinationAS = None
        self.sourceAS = None
        self.providerAS = None
        self.ASSequence = []

        self.noisyFirstEgress = None  #

        self.egressPoints = []  # list of egress points along the trace
        self.egressPointsByIP = {}  # same as above, but accessible by IP
        self.ingressPoints = []  # list of ingress points along the trace
        self.ingressPointsByIP = {}  # same as above, but accessible by IP
        self.ASInfo = {}  # contains all interesting info for each AS on the path (source AS and destination AS are not considered)

        self.CWEgressPoints = []  # campaign-wise egress points
        self.CWEgressPointsByIP = {}  # campaign-wise egress points (by ip)

    def __repr__(self):
        """
        """
        if self.ASHops != {}:
            rep = "{src}({srcAS})\t{dst}({dstAS})\t{dstReplied}:{destTTL}".format(src=self.source, dst=self.destination,
                                                                        dstReplied=self.destReplied, destTTL=self.destDistance,
                                                                        srcAS=self.sourceAS, dstAS=self.destinationAS)
        else:
            rep = "{src}\t{dst}\t{dstReplied}".format(src=self.source, dst=self.destination,
                                                      dstReplied=self.destReplied)

        # not too pythonic, but it works...
        for hop in self.hops:
            if self.ASHops != {}:
                for i in range(len(list(set(self.hops[hop])))):
                    if self.mplsInfo[hop] == {}:
                        rep += "\t{hop}:{ip}({AS});".format(hop=hop, ip=self.hops[hop][i], AS=self.ASHops[hop][i])
                    else:
                        rep += "\t{hop}:{ip}({AS})[M];".format(hop=hop, ip=self.hops[hop][i], AS=self.ASHops[hop][i])
                rep = rep.rstrip(";")
            # rep += "\t{ip}({AS})".format(ip=self.hops[hop][0], AS=self.ASHops[hop][0])
            else:
                for i in range(len(list(set(self.hops[hop])))):
                    if self.mplsInfo[hop] == {}:
                        rep += "\t{hop}:{ip};".format(hop=hop, ip=self.hops[hop][i])
                    else:
                        rep += "\t{hop}:{ip}[M];".format(hop=hop, ip=self.hops[hop][i])
                rep = rep.rstrip(";")

            if self.hops[hop][0] in self.egressPointsByIP:
                rep += "*"
        return rep

    def getSubTrace(self, startIP, stopIP):
        """
        Returns the part of the trace from startIP and stopIP (included)
        If either startIP or stopIP is not on the path, raises IpNotOnPathException.
        """

        ipList = [self.hops[k] for k in sorted(self.hops)]
        ipList = map(lambda x: x[0], ipList)
        try:
            startIndex = ipList.index(startIP)
        except ValueError, e:
            raise IpNotOnPathException("%s not found on the path towards %s" % (startIP, self.destination))
        try:
            stopIndex = ipList.index(stopIP)
        except ValueError, e:
            raise IpNotOnPathException("%s not found on the path towards %s" % (stopIP, self.destination))

        return tuple(ipList[startIndex: stopIndex + 1])

    def mplsHopsBefore(self, hopNum):
        """
        Returns how many hops expose MPLS labels ip to a given hopNum (hopNum included).
        """

        return len([x for x in self.mplsInfo if self.mplsInfo[x] != {} and x <= hopNum])

    def IP2ASMapping(self, mapper):
        """
        Performs IP2AS mapping on the whole trace, according to the information provided by the mapper object
        """

        for hopNum in self.hops:
            ipAddresses = self.hops[hopNum]  # list
            ASHops = []
            for ipAddress in ipAddresses:
                ASHops.append(mapper.mapIP(ipAddress))
            self.ASHops[hopNum] = ASHops

    def getIngressEgressPoints(self):
        """
        Look for first and last occurrence for each AS.
        """

        # last index search
        def rindex(mylist, myvalue):
            return len(mylist) - mylist[::-1].index(myvalue) - 1

        ingressPoints = []
        egressPoints = []

        ASHopList = [x[0] for x in
                     self.ASHops.values()]  # list of ASes associated to each hop crossed.
                                            # multiple IPs per hop not managed. Only the first one is taken into account

        ASSequence = []  # list of crossed ASes in order, no repetitions
        for AS in ASHopList:
            if AS not in ASSequence and AS not in ['q', None, 'Private']:
                ASSequence.append(AS)
        if self.destinationAS not in ASSequence and self.destReplied == 'R':
            ASSequence.append(self.destinationAS)
        self.ASSequence = ASSequence

        ASInfo = {}  # contains all interesting info for each AS on the path (source AS and destination AS are not considered)

        # for AS in set(ASHopList).difference(['q', 'Private', None, self.sourceAS, self.destinationAS]):
        # source and destination AS are not considered
        for AS in set(ASHopList).difference(['q', 'Private', None]):

            # egress
            lastOccurrenceIndex = rindex(ASHopList, AS)
            egrIP = self.hops[lastOccurrenceIndex][0]
            egrAS = self.ASHops[lastOccurrenceIndex][0]
            egrHopNum = lastOccurrenceIndex
            if lastOccurrenceIndex + 1 < len(self.hops):
                nextIP = self.hops[lastOccurrenceIndex + 1][0]
            else:
                nextIP = None
            if lastOccurrenceIndex + 1 < len(self.hops):
                nextAS = self.ASHops[lastOccurrenceIndex + 1][0]
            else:
                nextAS = None

            egressPoint = EgressPoint(egrIP, egrAS, nextIP, nextAS, egrHopNum)
            egressPoints.append(egressPoint)

            # Ingress
            firstOccurrenceIndex = ASHopList.index(AS)
            ingrIP = self.hops[firstOccurrenceIndex][0]
            ingrAS = self.ASHops[firstOccurrenceIndex][0]
            ingrHopNum = firstOccurrenceIndex
            if firstOccurrenceIndex - 1 >= 0:
                prevIP = self.hops[firstOccurrenceIndex - 1][0]
            else:
                prevIP = None
            if firstOccurrenceIndex - 1 >= 0:
                prevAS = self.ASHops[firstOccurrenceIndex - 1][0]
            else:
                prevAS = None

            ingressPoint = IngressPoint(ingrIP, ingrAS, prevIP, prevAS, ingrHopNum)
            ingressPoints.append(ingressPoint)

            ASInfo[AS] = ASOnPath(ingressPoint, egressPoint, self, AS)

        #                            {"ingressPoint": ingressPoint,
        #                          "egressPoint": egressPoint,
        #                          "ASLength" : egressPoint.hopNum - ingressPoint.hopNum +1,
        #                          "mplsHops" : self.mplsHopsBefore(egressPoint.hopNum) - self.mplsHopsBefore(ingressPoint.hopNum-1),
        #                          "originatingTrace" : self,
        #                          "AS" : AS
        #                    }

        self.egressPoints = egressPoints
        self.ingressPoints = ingressPoints
        self.ASInfo = ASInfo

        self.egressPointsByIP = {ep.ipAddress: ep for ep in egressPoints}
        self.ingressPointsByIP = {inp.ipAddress: inp for inp in ingressPoints}

    def markIngressEgressHops(self):
        """
        Generates two dictionary: EgressVector and IngressVector.
        A "True" value means that the hop with the corresponding key is the last/first IP seen along the path belonging to a given AS (for egressVector/ingressVector, respectively).
        self.noisyFirstEgress is set to True if missing values (q) are encountered before having marked the first egress.

        THIS HEURISTICS CAN BE REPLACED BY ANOTHER ONE WORKING ON THE AS SEQUENCE!!!

        """

        startTTL = 2

        firstEgressMarked = False
        noisyFirstEgress = False
        egressVector = {}
        ingressVector = {}

        for i in range(len(self.ASHops)):
            egressVector[i] = False
            ingressVector[i] = False

        if self.ASHops == {}:
            print ":: YOU SHOULD RUN IP2ASMapping first! ::"

        else:
            for i in range(startTTL, len(self.ASHops) - 1):
                currASHop = self.ASHops[i]
                nextASHop = self.ASHops[i + 1]

                if noisyFirstEgress == False and firstEgressMarked == False and (
                        nextASHop in [['q'], ['Private'], [None]] or currASHop in [['q'], ['Private'], [None]]):
                    noisyFirstEgress = True

                if currASHop not in [['q'], ['Private'], [None]] and nextASHop not in [['q'], ['Private'], [None]]:
                    if currASHop != nextASHop:
                        egressVector[i] = True
                        ingressVector[i + 1] = True
                        firstEgressMarked = True

        self.egressVector = egressVector
        self.ingressVector = ingressVector
        self.noisyFirstEgress = noisyFirstEgress

    def findAndSetProviderAS(self):
        """
        Identifies the upstream provider AS and set the related attribute.

        Needs to know ASHops and self.sourceAS
        """
        #        print self.sourceAS
        #        print self.ASSequence[0]
        #        print self.ASSequence[0] != self.sourceAS
        #        raw_input()
        try:
            if self.ASSequence[0] != self.sourceAS:
                providerAS = self.ASSequence[0]
            else:
                providerAS = self.ASSequence[1]
        except:
            providerAS = None
        self.providerAS = providerAS

    def findNthASOnPath(self, n):
        """
        0: source AS
        1: provider AS
        2 ...
        """

        if n == 0:
            return self.sourceAS
        elif n == 1:
            return self.providerAS
        else:
            try:
                return self.ASSequence[self.ASSequence.index(self.providerAS) + n - 1]
            except IndexError:
                # raised when AS sequnce is shorter...
                return None
                # raise NotSoManyASesOnPathException("%dth downstream AS not availavle in this trace"%n)
            except ValueError:
                # raised when self.providerAS = None
                return None

    #                print self
    #                print self.providerAS
    #                print self.ASSequence
    #                raw_input()

    def mapDestination(self, mapper):
        """
        Does IP2AS mapping for the destination.
        """
        self.destinationAS = mapper.mapIP(self.destination)

    def mapSource(self, mapper):
        """
        Does IP2AS mapping for the source.
        """
        self.sourceAS = mapper.mapIP(self.source)

    def getFirstEgressHop(self):
        """
        Returns the hop where the first egress IP is encountered.
        """
        try:
            retValue = self.egressVector.values().index(True)
        except ValueError:
            retValue = None
        return retValue

    def IP2ASMappingAndRelated(self, mapper):
        """
        Just a wrapper calling IP2ASMapping and function depending upon it.
        """
        self.IP2ASMapping(mapper)
        self.mapDestination(mapper)
        self.mapSource(mapper)
        # self.markIngressEgressHops()  # 1st heuristics
        self.getIngressEgressPoints()  # 2nd (alternative heuristics)
        self.findAndSetProviderAS()


class TraceCampaign():
    """
    A set of traces.
    Parses the dump file obtained leveraging *sc_analysisdump -M*.
    """

    def __init__(self, filename, format=Trace.SCAMPER_FORMAT):
        self.traces = []

        # if format == Trace.SCAMPER_FORMAT:
        if format == Trace.SCAMPER_FORMAT:
            rawLines = []
            with open(filename) as f:
                while True:
                    line = f.readline()
                    if line == "":
                        break
                    elif line.startswith("#"):
                        continue
                    else:
                        rawLines.append(line)

            for line in rawLines:
                self.traces.append(Trace(line, originatingCampaign=self))

        elif format == Trace.RIPEATLAS_FORMAT:

            with open(filename) as f:
                for x in json.load(f):
                    t = Trace(x, format=Trace.RIPEATLAS_FORMAT, originatingCampaign=self)
                    self.traces.append(t)

        # In case of multiple traces towards the same destination, this structure doesnt work well.
        # TODO:{"destIP" --> list of traces}
        self.tracesByDestination = {t.destination: t for t in self.traces}  # dictionary = {"destIP" --> trace}
        self.nickname = None
        self.ASOnPathInfoDict = defaultdict(dict)

    def IP2ASMappingAndRelated(self, mapper):
        """
        Just a wrapper.
        """
        for t in self.traces:
            t.IP2ASMappingAndRelated(mapper)

    def writeCampaignSummary(self, outFile=None):

        if outFile:
            summaryFile = outFile
        else:
            summaryFile = "%s-CAMPAIGNSUMMARY.txt" % self.nickname

        # absolute numbers
        totTracesNum = len(self.traces)
        completeTracesNum = len([t for t in self.traces if t.pathComplete == 'C'])
        incompleteTracesNum = len([t for t in self.traces if t.pathComplete == 'I'])
        destRepliedTracesNum = len([t for t in self.traces if t.destReplied == 'R'])
        destNotRepliedTracesNum = len([t for t in self.traces if t.destReplied == 'N'])
        mplsCrossingTracesNum = len([t for t in self.traces if t.mplsHopNum > 0])
        nullTracesNum = len([t for t in self.traces if t.hops == {}])

        # percentages
        completeTracesPctg = float(completeTracesNum) / totTracesNum
        incompleteTracesPctg = float(incompleteTracesNum) / totTracesNum
        destRepliedTracesPctg = float(destRepliedTracesNum) / totTracesNum
        destNotRepliedTracesPctg = float(destNotRepliedTracesNum) / totTracesNum
        mplsCrossingTracesPctg = float(mplsCrossingTracesNum) / totTracesNum
        nullTracesPctg = float(nullTracesNum) / totTracesNum

        sf = open(summaryFile, 'w')

        sf.write("::CAMPAIGN SUMMARY::\n")
        sf.write("Number of traces: %s\n" % totTracesNum)
        sf.write("--- complete (i.e. no missing hop):\t %s (%.2f %%)\n" % (completeTracesNum, completeTracesPctg * 100))
        sf.write("--- incomplete (i.e. with missing hops):\t %s (%.2f %%)\n" % (
            incompleteTracesNum, incompleteTracesPctg * 100))
        sf.write("--- null:\t\t\t\t %s (%.2f %%)\n" % (nullTracesNum, nullTracesPctg * 100))
        sf.write(
            "--- reaching the destination:\t\t %s (%.2f %%)\n" % (destRepliedTracesNum, destRepliedTracesPctg * 100))
        sf.write("--- not reaching the destination:\t %s (%.2f %%)\n" % (
            destNotRepliedTracesNum, destNotRepliedTracesPctg * 100))
        sf.write(
            "--- crossing MPLS tunnels:\t\t %s (%.2f %%)\n" % (mplsCrossingTracesNum, mplsCrossingTracesPctg * 100))

    def removeNullTraces(self):
        notNullTraces = [t for t in self.traces if t.hops != {}]
        self.traces = notNullTraces

    def getNullTraces(self):
        nullTraces = [t for t in self.traces if t.hops == {}]

        return {"stats":
                    {"nullTracesNum": len(nullTraces)},

                "details":
                    {"nullTracesList": nullTraces}
                }

    def filterOutTraces(self, listOfTraces):

        self.traces = list(set(self.traces).difference(set(listOfTraces)))

    #    def compare2(self, mapper, referenceCampaign):
    #        """
    #        DEPRECATED!
    #        Focuses only on provider AS for now (frist AS after sourceAS).
    #
    #        """
    #
    #        # first identify ep
    #        epOfInterest = []
    #        ASLengthInfo = {}
    #        distanceInfo = {}
    #        easyIP2AS = {}  # IP2AS mapping only for ep of interest
    #        for t in self.traces:
    ##            if t.ASHops == {}:
    ##                t.IP2ASMappingAndRelated(mapper)  # do IP2AS mapping on the whole trace - populates t.ASHops that is needed for tracing egress hops
    ##            if t.hops =={}:
    ##                continue
    #
    #            # look for the egress point of the provider AS
    #            try:
    #                if t.ASSequence[0] != t.sourceAS:
    #                    providerAS = t.ASSequence[0]
    #                else:
    #                    providerAS = t.ASSequence[1]
    #            except:
    #                providerAS = None
    #            if providerAS == None:
    #                continue
    #
    #            for ep in t.egressPoints:
    #                if ep.AS == providerAS:  # provider's egress point
    #                    if ep.isNoisy:
    #                        pass  # discard noisy egress points
    #                    else:
    #                        epOfInterest.append(ep)
    #                        easyIP2AS[ep.ipAddress] = ep.AS
    #
    ##                        ASLen = t.ASInfo[providerAS]["ASLength"]
    #                        ASLen = t.ASInfo[providerAS].ASLength
    #
    #                        if ep.ipAddress in ASLengthInfo:
    #                            ASLengthInfo[ep.ipAddress].update([ASLen])
    #                        else:
    #                            ASLengthInfo[ep.ipAddress] = Counter([ASLen])
    #
    #                        if ep.ipAddress in distanceInfo:
    #                            distanceInfo[ep.ipAddress].update([ep.hopNum+1])
    #                        else:
    #                            distanceInfo[ep.ipAddress] = Counter([ep.hopNum+1])
    #
    #
    #        directDistance = {}
    #        for t in referenceCampaign.traces:
    #            directDistance[t.destination] = int(t.destDistance)
    #
    #        epNum = len(distanceInfo)  # number of egress points investigated
    #        nonRespEpList = [dest for dest in directDistance if directDistance[dest] == 0]
    #        nonRespEpList = list(set(nonRespEpList).intersection(set(distanceInfo.keys())))
    #        nonRespEpNum = len(nonRespEpList)
    #
    #        respEpList = [dest for dest in directDistance if directDistance[dest] != 0]
    #        respEpList = list(set(respEpList).intersection(set(distanceInfo.keys())))
    #        respEpNum = len(respEpList)
    #
    #        missingTargetsList = list(set(distanceInfo.keys()).difference(set(directDistance.keys())))
    #        missingTargetsListNum = len(missingTargetsList)
    #
    #        analyzeableEpList = list(set(distanceInfo.keys()).difference(set(nonRespEpList)).difference(set(missingTargetsList)))
    #        analyzeableEpListNum = len(analyzeableEpList)
    #
    #        fluctuatingDistanceEpList = [ip for ip in set(distanceInfo.keys()).intersection(set(analyzeableEpList)) if len(distanceInfo[ip].keys()) > 1]  # fluctuating distance when transit
    #        fluctuatingDistanceEpListNum = len(fluctuatingDistanceEpList)
    #        stableDistanceEpList = [ip for ip in set(distanceInfo.keys()).intersection(set(analyzeableEpList)) if len(distanceInfo[ip].keys()) == 1]  # same distance when transit
    #        stableDistanceEpListNum = len(stableDistanceEpList)
    #
    #        stable_d_gt_t = []
    #        stable_d_eq_t = []
    #        stable_d_lt_t = []
    #
    #        for ip in stableDistanceEpList:
    #
    #            dd = int(directDistance[ip])
    #            td = distanceInfo[ip].keys()[0]
    #
    #            if dd > td:
    #                stable_d_gt_t.append(ip)
    #            elif dd == td:
    #                stable_d_eq_t.append(ip)
    #            else:
    #                stable_d_lt_t.append(ip)
    #
    #        # considering max len (default)
    #        fluctuating_d_gt_t = []
    #        fluctuating_d_eq_t = []
    #        fluctuating_d_lt_t = []
    #
    #        # considerign min len
    #        fluctuating_d_gt_tmin = []
    #        fluctuating_d_eq_tmin = []
    #        fluctuating_d_lt_tmin = []
    #
    #        for ip in fluctuatingDistanceEpList:
    #            dd = int(directDistance[ip])
    #            td = max(distanceInfo[ip])
    #            tdmin = min(distanceInfo[ip])
    #
    #            if dd > td:
    #                fluctuating_d_gt_t.append(ip)
    #            elif dd == td:
    #                fluctuating_d_eq_t.append(ip)
    #            else:
    #                fluctuating_d_lt_t.append(ip)
    #
    #            if dd > tdmin:
    #                fluctuating_d_gt_tmin.append(ip)
    #            elif dd == tdmin:
    #                fluctuating_d_eq_tmin.append(ip)
    #            else:
    #                fluctuating_d_lt_tmin.append(ip)
    #
    #
    #        print "\n\n::TRANSIT vs DIRECT (summary)::"
    #        print "Egress points under investigation:\t%s" % epNum
    #        try:
    #            print "--- responding:\t\t\t\t%s (%.2f %%)" % (respEpNum, float(respEpNum)*100/epNum)
    #            print "--- non responding:\t\t\t%s (%.2f %%)" % (nonRespEpNum, float(nonRespEpNum)*100/epNum)
    #            print "--- not probed:\t\t\t\t%s (%.2f %%)" % (missingTargetsListNum, float(missingTargetsListNum)*100/epNum)
    #            print "--- analyzeable:\t\t\t%s (%.2f %%)" % (analyzeableEpListNum, float(analyzeableEpListNum)*100/epNum)
    #        except ZeroDivisionError:
    #            return
    #
    #        try:
    #            print "------ fluctuating distance (transit):\t%s (%.2f %%)" % (fluctuatingDistanceEpListNum, (float(fluctuatingDistanceEpListNum))*100/analyzeableEpListNum)
    #            print "--------- D > max(T):\t%s (%.2f %%)" % (len(fluctuating_d_gt_t), float(len(fluctuating_d_gt_t))*100/fluctuatingDistanceEpListNum)
    #            print "--------- D = max(T):\t%s (%.2f %%)" % (len(fluctuating_d_eq_t), float(len(fluctuating_d_eq_t))*100/fluctuatingDistanceEpListNum)
    #            print "--------- D < max(T):\t%s (%.2f %%)" % (len(fluctuating_d_lt_t), float(len(fluctuating_d_lt_t))*100/fluctuatingDistanceEpListNum)
    #            print "---------"
    #            print "--------- D > min(T):\t%s (%.2f %%)" % (len(fluctuating_d_gt_tmin), float(len(fluctuating_d_gt_tmin))*100/fluctuatingDistanceEpListNum)
    #            print "--------- D = min(T):\t%s (%.2f %%)" % (len(fluctuating_d_eq_tmin), float(len(fluctuating_d_eq_tmin))*100/fluctuatingDistanceEpListNum)
    #            print "--------- D < min(T):\t%s (%.2f %%)" % (len(fluctuating_d_lt_tmin), float(len(fluctuating_d_lt_tmin))*100/fluctuatingDistanceEpListNum)
    #        except ZeroDivisionError:
    #            pass
    #
    #        try:
    #            print "------ stable distance (transit):\t%s (%.2f %%)" % (stableDistanceEpListNum, float(stableDistanceEpListNum)*100/analyzeableEpListNum)
    #            print "--------- D > T:\t%s (%.2f %%)" % (len(stable_d_gt_t), float(len(stable_d_gt_t))*100/stableDistanceEpListNum)
    #            print "--------- D = T:\t%s (%.2f %%)" % (len(stable_d_eq_t), float(len(stable_d_eq_t))*100/stableDistanceEpListNum)
    #            print "--------- D < T:\t%s (%.2f %%)" % (len(stable_d_lt_t), float(len(stable_d_lt_t))*100/stableDistanceEpListNum)
    #        except ZeroDivisionError:
    #            pass
    #
    #
    #        if fluctuatingDistanceEpList != []:
    #            print "\n::EGRESS POINTS WITH FLUCTUATING DISTANCE::"
    #        i = 0
    #        for ip in sorted(fluctuatingDistanceEpList, key= lambda x: easyIP2AS[x]):
    #            i += 1
    #            distances = distanceInfo[ip].keys()
    #            occurrences = distanceInfo[ip].values()
    #            ASLengths = ASLengthInfo[ip].keys()
    #            ASLengthsOccurrences = ASLengthInfo[ip].values()
    #
    #            print "%5sF Transit:\t%s\t%s\t%s\t%s" % (i, easyIP2AS[ip], ip, distances, occurrences)
    #            #print "Transit: %s\t%s\t%s" % (ip, distances, ["{0:0.2f}".format(i) for i in map(lambda x: float(x)/sum(occurrences), occurrences)])
    #            print "%5sF Direct:\t%s\t%s\t%s" % (i, easyIP2AS[ip], ip, directDistance[ip])
    #            #print "%5sF Transit (ASLen):\t%s\t%s\t%s\t%s" % (i, easyIP2AS[ip], ip, ASLengths, ASLengthsOccurrences)
    #            print ""
    #
    #        if stableDistanceEpList != []:
    #            print "\n::EGRESS POINTS WITH STABLE DISTANCE::"
    #        i = 0
    #        for ip in sorted(stableDistanceEpList, key= lambda x: easyIP2AS[x]):
    #            i += 1
    #            distances = distanceInfo[ip].keys()
    #            occurrences = distanceInfo[ip].values()
    #            ASLengths = ASLengthInfo[ip].keys()
    #            ASLengthsOccurrences = ASLengthInfo[ip].values()
    #
    #            print "%5sS Transit:\t%s\t%s\t%s\t%s" % (i, easyIP2AS[ip], ip, distances,  occurrences)
    #            #print "Transit: %s\t%s\t%s" % (ip, distances, ["{0:0.2f}".format(i) for i in map(lambda x: float(x)/sum(occurrences), occurrences)])
    #            print "%5sS Direct:\t%s\t%s\t%s" % (i, easyIP2AS[ip], ip, directDistance[ip])
    #            #print "%5sS Transit (ASLen):\t%s\t%s\t%s\t%s" % (i, easyIP2AS[ip], ip, ASLengths, ASLengthsOccurrences)
    #            print ""
    #
    #
    #        return {"stable_d_gt_t": stable_d_gt_t}  # could be a TraceCampaign member

    #    def filterTraces(self, epASes=[], epIPs = [], referenceCampaign=None):
    #        """
    #        Filter traces based on the egress points.
    #        Returns traces with egress points in epASes list *AND* whose IP address belongs to epIPs list.
    #        """
    #
    #        for t in self.traces:
    #            for ip  in set(t.egressPointsByIP.keys()).intersection(set(epIPs)):
    #                if t.egressPointsByIP[ip].AS in epASes:
    #
    #                    print ip
    #                    print t.egressPointsByIP[ip].AS
    #
    #                    print t
    #                    if referenceCampaign:
    #                        print referenceCampaign.tracesByDestination[ip]
    #                    print "---"
    #                    raw_input()

    def writeEgressPointList_MDAFormat(self, outBaseName=None):
        """
        Generates <NICKNAME>-firstegress-mda-startingfrom<N>.ips
        """
        if not outBaseName:
            firsteplistBaseName = "%s-firstegress-mda" % self.nickname
        else:
            firsteplistBaseName = outBaseName

        firstipdict = defaultdict(list)

        for t in self.traces:
            if not (t.providerAS == None or t.providerAS == t.destinationAS):
                # first egress point in the trace (provider AS)
                firstIP = t.ASInfo[t.providerAS].egressPoint.ipAddress  # one obj per trace, at most.
                startingTTLforMDA = t.ASInfo[t.providerAS].ingressPoint.hopNum + 1
                firstipdict[startingTTLforMDA].append(firstIP)

        for sTTL in firstipdict:
            firstipdict[sTTL] = list(set(firstipdict[sTTL]))
            outFile = "%s-startingfrom%s.ips" % (firsteplistBaseName, sTTL)

            of = open(outFile, 'w')
            for ip in firstipdict[sTTL]:
                of.write("{}\n".format(ip))
            of.close()

    def writeFirstEgressPointListWithNextIps(self, outFileName=None):
        """
        Generates <NICKNAME>-egress.ips and  <NICKNAME>-firstegress.ips
        The list containst the list of the Provider AS egress points.
        """

        if not outFileName:
            firsteplistFileName = "%s-firstegress-withNextIps.ips" % self.nickname
        else:
            firsteplistFileName = outFileName

        iplist = []
        firstiplist = []

        nextIpAddresses = defaultdict(list)

        for t in self.traces:
            if not (t.providerAS == None or t.providerAS == t.destinationAS):

                # first egress point in the trace (provider AS)
                firstIP = t.ASInfo[t.providerAS].egressPoint.ipAddress  # one obj per trace, at most.
                nextIP = t.ASInfo[t.providerAS].egressPoint.nextIpAddress

                # print firstIP, nextIP

                if nextIP:
                    nextIpAddresses[firstIP].append(nextIP)
                firstiplist.append(firstIP)

            for AS in t.ASInfo:
                # all egress points
                iplist.append(t.ASInfo[AS].egressPoint.ipAddress)

        iplist = list(set(iplist))
        firstiplist = list(set(firstiplist))

        feplf = open(firsteplistFileName, 'w')
        for firstip in firstiplist:
            feplf.write("{ip}, {nextips}\n".format(ip=firstip, nextips=";".join(list(set(nextIpAddresses[firstip])))))
        feplf.close()

    def writeStatistics(self, outFileName):
        """
        Generates <NICKNAME>-egress.ips and  <NICKNAME>-firstegress.ips
        The list containst the list of the Provider AS egress points.
        """
        ingresses = set()
        egresses = set()
        i_e_couples = set()
        crossed_ASes = set()
        q_internal_routes = 0
        for t in self.traces:
            for AS in t.ASInfo:
                if AS not in [t.sourceAS, t.destinationAS, t.ASSequence[-1]]:
                    q_internal_routes += 1
                    in_p = t.ASInfo[AS].ingressPoint.ipAddress
                    out_p = t.ASInfo[AS].egressPoint.ipAddress
                    ingresses.add(in_p)
                    egresses.add(out_p)
                    i_e_couples.add((in_p, out_p))
                    crossed_ASes.add(AS)

        str_ingresses = ','.join(str(ip) for ip in list(ingresses))
        str_egresses = ','.join(str(ip) for ip in list(egresses))
        str_couples = ",".join(str(c[0]) + '|' + str(c[1]) for c in (list(i_e_couples)))
        str_ASes = ",".join(str(AS) for AS in crossed_ASes)

        eplf = open(outFileName, 'w')
        eplf.write("{q_in};{q_out};{q_couples};{q_AS};{q_internal_routes};{q_traces}\n".format(q_in = str_ingresses,
                                                                             q_out = str_egresses,
                                                                             q_couples = str_couples,
                                                                             q_AS = str_ASes,
                                                                             q_internal_routes = q_internal_routes,
                                                                             q_traces = len(self.traces)))

        # eplf.write("{q_in},{q_out},{q_couples},{q_internal_routes},{q_traces}\n".format(q_in = len(ingresses),
        #                                                                      q_out = len(egresses),
        #                                                                      q_couples = len(i_e_couples),
        #                                                                      q_internal_routes = q_internal_routes,
        #                                                                      q_traces = len(self.traces)))
        eplf.close()

    def writeEgressPointList(self, outFileName=None, outFileName2=None):
        """
        Generates <NICKNAME>-egress.ips and  <NICKNAME>-firstegress.ips
        The list containst the list of the Provider AS egress points.
        """

        if not outFileName:
            eplistFileName = "%s-egress.ips" % self.nickname
        else:
            eplistFileName = outFileName

        if not outFileName2:
            firsteplistFileName = "%s-firstegress.ips" % self.nickname
        else:
            firsteplistFileName = outFileName2

        iplist = []
        firstiplist = []

        for t in self.traces:
            if not (t.providerAS == None or t.providerAS == t.destinationAS) and t.providerAS != t.ASSequence[-1]:
                # first egress point in the trace (provider AS)
                firstIP = t.ASInfo[t.providerAS].egressPoint.ipAddress  # one obj per trace, at most.
                firstiplist.append(firstIP)

            for AS in t.ASInfo:
                if AS != t.ASSequence[-1]:  # exclude the last AS on the path (we dont know if it is an Egress Point, actually)
                    # all egress points
                    iplist.append(t.ASInfo[AS].egressPoint.ipAddress)

        iplist = list(set(iplist))
        firstiplist = list(set(firstiplist))

        eplf = open(eplistFileName, 'w')
        for ip in iplist:
            eplf.write("{ip}\n".format(ip=ip))
        eplf.close()

        feplf = open(firsteplistFileName, 'w')
        for firstip in firstiplist:
            feplf.write("{ip}\n".format(ip=firstip))
        feplf.close()

    def getCWEgressPoints(self, referenceCampaign=None, mdaCampaign=None, ASDistance=1):
        """
        Focuses on provider AS by default.

        null traces filtered out upstream
        ip2as mapping (and related) done upstream

        """

        # first identify ep
        ASInfoList = []  # contains not only the egress point information, but also that related to the AS it belongs to (ingress, and metrics)
        for t in self.traces:
            focusAS = t.findNthASOnPath(ASDistance)
            if focusAS == None or focusAS == t.destinationAS:
                continue
            try:
                asOccurrence = t.ASInfo[focusAS]  # one obj per trace, at most.
                ASInfoList.append(asOccurrence)
            except Exception, e:
                print "exception in getCWEgressPoints"
                print e.message
                raw_input()

        # ASInfoList_noisyEp = [x for x in ASInfoList if x.egressPoint.isNoisy]
        ASInfoByIP = defaultdict(list)
        for x in ASInfoList:
            ASInfoByIP[x.egressPoint.ipAddress].append(x)
        # ASInfoList = list(set(ASInfoList).difference(set(ASInfoList_noisyEp)))  # remove noisy egress points

        ASList = [x.AS for x in ASInfoList]
        ASCounter = Counter(ASList)

        IPList = [x.egressPoint.ipAddress for x in ASInfoList]
        IPCounter = Counter(IPList)

        AStoIP = {}  # needed mainly to improve performance
        for AS in ASCounter:
            AStoIP[AS] = list(set([x.egressPoint.ipAddress for x in ASInfoList if x.AS == AS]))

        ASOnPathInfo = {}  # for ASOnPath metrics related to MPLSTunnelCount and AS len - and comparison with direct trace
        cwepL = []
        for ip in ASInfoByIP:
            try:
                directTrace = referenceCampaign.tracesByDestination[ip] if (
                        referenceCampaign and ip in referenceCampaign.tracesByDestination) else None
            except KeyError, e:
                print e
                raw_input()

            try:
                transitTraces = ASInfoByIP[ip]
            except KeyError, e:
                print e
                raw_input()

            try:
                mdaTrace = mdaCampaign.tracesByDestination[ip] if (
                        mdaCampaign and ip in mdaCampaign.tracesByDestination) else None

            except KeyError, e:
                print e
                raw_input()

            if not directTrace:
                print "NO DIRECT TRACE for %s" % ip
                continue

            try:
                cwep = CWEgressPoint(transitTraces, directTrace, mdaTrace, excludeNoisy=True)  # transit traces are TIRs
                #                if cwep.ipAddress == "193.51.181.93":
                #                    pprint(cwep.__dict__)
                #                    raw_input()
                # each of the following reinitializes cwep after filtering, so structures are always up-to-date
                cwep.excludeShortASes(3)
                cwep.excludeDifferentIngressPoints()
                cwep.excludeDifferentASSeqs()
                cwep.excludeDistanceOutliers()
                # cwep.excludeUnderSampled(20)
                cwep.excludeUnderSampled(10)

                info = cwep.getASOnPathInfo()  # extend dictionary with info related to another Egress Point
                for k in info:
                    ASOnPathInfo[k] = info[k]

                # pprint (cwep.__dict__)
                #                pprint(cwep.ipAddress)
                #                pprint (cwep.hasMDAdirectSubPath)
                #                pprint (cwep.MDAdirectSubPathsSet)
                #                raw_input()

                if cwep.hasMDAdirectSubPath:
                    print "transit"
                    pprint(sorted(cwep.transitSubPathsSet, key=lambda x: cwep.transitSubPathsC[x], reverse=True))
                    print "direct"
                    pprint(sorted(cwep.MDAdirectSubPathsSet, key=lambda x: cwep.MDAdirectSubPathsC[x], reverse=True))

                    print "different transit paths", cwep.transitSubPathsCard, sorted(cwep.transitSubPathsOcc,
                                                                                      reverse=True)
                    print "different direct paths", cwep.MDAdirectSubPathsCard, sorted(cwep.MDAdirectSubPathsOcc,
                                                                                       reverse=True)
                    print "intersection size", len(cwep.transitSubPathsSet.intersection(cwep.MDAdirectSubPathsSet)), [
                        cwep.transitSubPathsC[x] for x in
                        cwep.transitSubPathsSet.intersection(cwep.MDAdirectSubPathsSet)]
                    print ">>> %s" % cwep.mdadt_overlap
                    # raw_input()

                # cwep not appended to cwepL in case of DirectTraceRemovedWhileSkippingException
                cwepL.append(cwep)

            except DirectTraceRemovedWhileSkippingException, e:
                print "FILTER:", e
            except AllNoisyException, e:
                print "FILTER:", e
                continue  # if all noisy just discard the CWEgressPoint
            except AllShortException, e:
                print "FILTER:", e
                continue  # if all short just discard the CWEgressPoint
            except AllDifferentIngressException, e:
                print "FILTER:", e
                continue  # if all direct paths enter the AS through a different ingress just discard the CWEgressPoint
            except AllDifferentASPathException, e:
                print "FILTER:", e
                continue
            except UnderSampledException, e:
                print "FILTER:", e
                continue
            except MultipleEgressesException, e:
                print e
                sys.exit()
            except MultipleASesException, e:
                print e
                sys.exit()
            #            except Exception:
            #                pprint(cwep.__dict__)
            #                raw_input()



        self.ASOnPathInfoDict[ASDistance] = ASOnPathInfo
        self.CWEgressPoints = cwepL
        self.CWEgressPointsByIP = {x.ipAddress: x for x in cwepL}
        

    def getCWEgressPoints2(self, referenceCampaign=None, dstMDA=None, ASDistance=1):
        """
        Focuses on provider AS by default.

        null traces filtered out upstream
        ip2as mapping (and related) done upstream

        """

        # first identify ep
        ASInfoList = []  # contains not only the egress point information, but also that related to the AS it belongs to (ingress, and metrics)
        for t in self.traces:
            focusAS = t.findNthASOnPath(ASDistance)
            if focusAS is None or focusAS == t.destinationAS:
                continue
            try:
                asOccurrence = t.ASInfo[focusAS]  # one obj per trace, at most.
                ASInfoList.append(asOccurrence)
            except Exception, e:
                print "exception in getCWEgressPoints"
                print e.message
                raw_input()

        # ASInfoList_noisyEp = [x for x in ASInfoList if x.egressPoint.isNoisy]
        ASInfoByIP = defaultdict(list)
        for x in ASInfoList:
            ASInfoByIP[x.egressPoint.ipAddress].append(x)

        ASList = [x.AS for x in ASInfoList]
        ASCounter = Counter(ASList)

        IPList = [x.egressPoint.ipAddress for x in ASInfoList]
        IPCounter = Counter(IPList)

        AStoIP = {}  # needed mainly to improve performance
        for AS in ASCounter:
            AStoIP[AS] = list(set([x.egressPoint.ipAddress for x in ASInfoList if x.AS == AS]))

        ASOnPathInfo = {}  # ASOnPath metrics related to MPLSTunnelCount and AS len
                           # comparison with direct trace and MDA trace

        cwepL = []
        for ip in ASInfoByIP:
            try:
                directTrace = referenceCampaign.tracesByDestination[ip] if (
                        referenceCampaign and ip in referenceCampaign.tracesByDestination) else None
            except KeyError, e:
                print e
                raw_input()

            try:
                transitTraces = ASInfoByIP[ip]
            except KeyError, e:
                print e
                raw_input()

            if not directTrace:
                print "NO DIRECT TRACE for %s" % ip
                continue

            try:
                cwep = CWEgressPoint2(transitTraces, directTrace, dstMDA, excludeNoisy=True)
                # each of the following reinitializes cwep after filtering, so structures are always up-to-date
                cwep.excludeShortASes(3)
                cwep.excludeDifferentIngressPoints()
                cwep.excludeDifferentASSeqs()
                cwep.excludeDistanceOutliers()
                # cwep.excludeUnderSampled(20)
                cwep.excludeUnderSampled(10)

                info = cwep.getASOnPathInfoYYY()  # extend dictionary with info related to another Egress Point
                for k in info:
                    ASOnPathInfo[k] = info[k]


            except AllNoisyException, e:
                print "FILTER:", e
                continue  # if all noisy just discard the CWEgressPoint
            except AllShortException, e:
                print "FILTER:", e
                continue  # if all short just discard the CWEgressPoint
            except AllDifferentIngressException, e:
                print "FILTER:", e
                continue  # if all direct paths enter the AS through a different ingress just discard the CWEgressPoint
            except AllDifferentASPathException, e:
                print "FILTER:", e
                continue
            except UnderSampledException, e:
                print "FILTER:", e
                continue
            except MultipleEgressesException, e:
                print e
                sys.exit()
            except MultipleASesException, e:
                print e
                sys.exit()
            #            except Exception:
            #                pprint(cwep.__dict__)
            #                raw_input()
            cwepL.append(cwep)

        self.ASOnPathInfoDict[ASDistance] = ASOnPathInfo
        self.CWEgressPoints = cwepL
        self.CWEgressPointsByIP = {x.ipAddress: x for x in cwepL}

        
    def write_incfibte_summary(self, outFileName=None, level=None):
        """
        
        """
        if not outFileName:
            if not level:
                level = "X"
            eplistFileName = "%s-L%s-INCFIBvsTE.csv" % (self.nickname, level)
        else:
            eplistFileName = outFileName

        of = open(eplistFileName, "w")
        CWEgressPoint2.print_incfib_vs_te_info_header()
        of.write(CWEgressPoint2.dump_incfib_vs_te_info_header()+"\n")
        for cwep in self.CWEgressPoints:
            info =  cwep.get_incfib_vs_te_info()
            
            CWEgressPoint2.print_incfib_vs_te_info(info)
            of.write(CWEgressPoint2.dump_incfib_vs_te_info(info)+"\n")



    def writePerTraceSummary(self):
        """
        generates a CSV from self.ASOnPathInfoDict
        """

        filename = "%s-pertrace-SUMMARY.csv" % self.nickname
        f = open(filename, "w")

        header = ";".join(["#{level}",
                           "{AS}",
                           "{IN}",
                           "{OUT}",
                           "{DST}",
                           "{M_T}",
                           "{M_H}",
                           "{T_d}",
                           "{T_t}",
                           "{H_d}",
                           "{H_t}",
                           "{M_RTT}",
                           "{dups_in_dir}",
                           "{dups_in_tir}",
                           "{HTunnel}",
                           "{VP}"
                           ]).format(level="level",
                                              AS="AS",
                                              IN="IN",
                                              OUT="OUT",
                                              DST="DST",
                                              M_T="M_T",
                                              M_H="M_H",
                                              T_d="T_d",
                                              T_t="T_t",
                                              H_d="H_d",
                                              H_t="H_t",
                                              M_RTT="M_RTT",
                                              dups_in_dir="dups_in_dir",
                                              dups_in_tir="dups_in_tir",
                                              HTunnel="Htunnel",
                                              VP="VP"
                                              )
        f.write("%s\n" % header)
        for level in self.ASOnPathInfoDict:
            for k in self.ASOnPathInfoDict[level]:
                s1 = "{level}".format(level=level)

                s2 = ";".join(["{AS}",
                               "{IN}",
                               "{OUT}",
                               "{DST}",
                               "{M_T}",
                               "{M_H}",
                               "{T_d}",
                               "{T_t}",
                               "{H_d}",
                               "{H_t}",
                               "{M_RTT}",
                               "{dups_in_dir}",
                               "{dups_in_tir}",
                               "{HTunnel}",
                               "{VP}"
                               ]).format(**self.ASOnPathInfoDict[level][k])

                f.write(";".join([s1, s2 + "\n"]))

    def writePerTraceSummary2(self):
        """
        generates a CSV from self.ASOnPathInfoDict
        """

        filename = "%s-pertrace-SUMMARY.csv" % self.nickname
        f = open(filename, "w")

        header = ";".join(["#{level}",
                           "{AS}",
                           "{IN}",
                           "{OUT}",
                           "{DST}",
                           "{M_T}",
                           "{M_H}",
                           "{T_d}",
                           "{T_t}",
                           "{H_d}",
                           "{H_t}",
                           "{M_RTT}",
                           "{ECMP}"]).format(level="level",
                                              AS="AS",
                                              IN="IN",
                                              OUT="OUT",
                                              DST="DST",
                                              M_T="M_T",
                                              M_H="M_H",
                                              T_d="T_d",
                                              T_t="T_t",
                                              H_d="H_d",
                                              H_t="H_t",
                                              M_RTT="M_RTT",
                                              ECMP="ECMP")
        f.write("%s\n" % header)
        for level in self.ASOnPathInfoDict:
            for k in self.ASOnPathInfoDict[level]:
                s1 = "{level}".format(level=level)

                s2 = ";".join(["{AS}",
                               "{IN}",
                               "{OUT}",
                               "{DST}",
                               "{M_T}",
                               "{M_H}",
                               "{T_d}",
                               "{T_t}",
                               "{H_d}",
                               "{H_t}",
                               "{M_RTT}",
                               "{ECMP}"]).format(**self.ASOnPathInfoDict[level][k])

                f.write(";".join([s1, s2 + "\n"]))


    def dumpDestMDAInput(self):
        """
        generates a CSV from self.ASOnPathInfoDict
        AS; I; E; DST; paths_match; transit_subpath; direct_subpath
        """

        filename = "%s-pertrace-MDAInput.csv" % self.nickname
        f = open(filename, "w")

        header = ";".join(["#{AS}",
                           "{IN}",
                           "{OUT}",
                           "{DST}",
                           "{paths_match}",
                           "{sub_t}",
                           "{sub_d}"]).format(
            AS="AS",
            IN="IN",
            OUT="OUT",
            DST="DST",
            paths_match="paths_match",
            sub_t="transit_path",
            sub_d="direct_path")

        f.write("%s\n" % header)
        for level in self.ASOnPathInfoDict:
            for k in self.ASOnPathInfoDict[level]:
                s = ";".join(["{AS}",
                              "{IN}",
                              "{OUT}",
                              "{DST}",
                              "{subpathsMatch}",
                              "{sub_t}",
                              "{sub_d}"]).format(**self.ASOnPathInfoDict[level][k])

                f.write(s + "\n")

    def writePerTraceMetricCorrelationSummary(self):
        """
        computes correlation among per path metrics.
        """

        def implications(d):

            A = 1 if d["M_T"] == "W" and (d["M_H"] == "<" or d["M_H"] == ">") else 0
            B = 1 if d["M_T"] == "W" else 0
            C = 1 if (d["M_H"] == "<" or d["M_H"] == ">") else 0

            return A, B, C

        filename = "%s-pertrace-correlation.txt" % self.nickname
        f = open(filename, "w")

        # ASList = list(set([(level, AS) for level in self.ASOnPathInfoDict for AS in self.ASOnPathInfoDict[level]]))

        A_dict = defaultdict(int)
        B_dict = defaultdict(int)
        C_dict = defaultdict(int)

        for level in self.ASOnPathInfoDict:
            for k in self.ASOnPathInfoDict[level]:
                AS = self.ASOnPathInfoDict[level][k]["AS"]

                A, B, C = implications(self.ASOnPathInfoDict[level][k])
                # pprint(A_dict)
                # pprint(B_dict)
                # pprint(C_dict)
                A_dict[AS] += A
                B_dict[AS] += B
                C_dict[AS] += C

        for AS in A_dict:
            try:
                H_implies_T_ratio = 100 * float(A_dict[AS]) / C_dict[AS]
            except ZeroDivisionError, e:
                H_implies_T_ratio = 0

            try:
                T_implies_H_ratio = 100 * float(A_dict[AS]) / B_dict[AS]
            except ZeroDivisionError, e:
                T_implies_H_ratio = 0

            f.write("{}\n".format(AS))
            f.write("H --> T:\t{A}/{C} ({ratio:.2f}%)\n".format(A=A_dict[AS], C=C_dict[AS], ratio=H_implies_T_ratio))
            f.write("T --> H:\t{A}/{B} ({ratio:.2f}%)\n\n".format(A=A_dict[AS], B=B_dict[AS], ratio=T_implies_H_ratio))

    def writeCWEgressSummary(self, cwEgressList=None, OutfileName=None):
        """
        """

        undersampled_tresh = 10

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        if not OutfileName:
            summaryFileName = "%s-SUMMARY.txt" % self.nickname
        else:
            summaryFileName = OutfileName

        ASList = [x.AS for x in cwEgressPoints]
        ASCounter = Counter(ASList)
        ASNum = len(ASCounter)

        IPList = [x.ipAddress for x in cwEgressPoints]
        IPCounter = Counter(IPList)
        IPNum = len(IPCounter)

        allNoisy = [x for x in cwEgressPoints if x.allNoisy == True]
        allNoisyNum = len(allNoisy)

        allNoisyAS = set([x.AS for x in allNoisy])
        allNoisyASNum = len(allNoisyAS)

        notNoisy = [x for x in cwEgressPoints if x.allNoisy == False]
        notNoisyNum = len(notNoisy)

        notNoisyAS = set([x.AS for x in notNoisy])
        notNoisyASNum = len(notNoisyAS)

        AStoIP = {}  # needed mainly to improve performance
        for AS in ASCounter:
            AStoIP[AS] = list(set([x.ipAddress for x in cwEgressPoints if x.AS == AS]))

        withDirectTrace = len([x for x in cwEgressPoints if x.hasDirectTrace])  # probed

        replying = [x for x in notNoisy if (x.hasDirectTrace and x.directTrace.destReplied == 'R')]  # responding
        replyingNum = len(replying)  # responding

        replyingAS = set([x.AS for x in replying])
        replyingASNum = len(replyingAS)

        notUndersampled = [x for x in replying if x.occ >= undersampled_tresh]
        notUndersampledNum = len(notUndersampled)

        notUndersampledAS = set([x.AS for x in notUndersampled])
        notUndersampledASNum = len(notUndersampledAS)

        undersampled = [x for x in replying if x.occ < undersampled_tresh]
        undersampledNum = len(undersampled)

        undersampledAS = set([x.AS for x in undersampled])
        undersampledASNum = len(undersampledAS)

        stableDistance = [x for x in notUndersampled if x.t_distanceStability == CWEgressPoint.STABLE_LABEL]
        stableDistanceNum = len(stableDistance)

        stableDistanceAS = set([x.AS for x in stableDistance])
        stableDistanceASNum = len(stableDistanceAS)

        fluctuatingDistance = set([x for x in notUndersampled if x.t_distanceStability == CWEgressPoint.VARIABLE_LABEL])
        fluctuatingDistanceNum = len(fluctuatingDistance)

        fluctuatingDistanceAS = set([x.AS for x in fluctuatingDistance])
        fluctuatingDistanceASNum = len(fluctuatingDistanceAS)

        incFIB1 = [x for x in notUndersampled if x.FIBInconsistencyMetricABS > 0]  # D<T
        incFIB1Num = len(incFIB1)

        incFIB1AS = set([x.AS for x in incFIB1])
        incFIB1ASNum = len(incFIB1AS)

        # CLASSIFICATION
        cwepClassificationSignatures = []
        cwepClassificationCodes = []
        for cwep in notUndersampled:
            cwepClassificationSignatures.append(cwep.DTVector())
            cwepClassificationCodes.append(cwep.classification())

            # print "\n%s" % cwep.ipAddress
            # print cwep.DTVector(), CWEgressPoint.translateCode(cwep.classification())
            # print "%.2f %%" % cwep.t_percMaxDistance

        cwepClassificationSignaturesC = Counter(cwepClassificationSignatures)
        cwepClassificationCodesC = Counter(cwepClassificationCodes)

        # print ""
        # for k in cwepClassificationCodesC:
        #    print cwepClassificationCodesC[k], CWEgressPoint.translateCode(k)

        # cases = set(cwepClassificationL)
        # pprint(cases)
        # print len(cwepClassificationCodesC)
        # raw_input()

        sfn = open(summaryFileName, 'w')

        try:
            print "Egress points initially under investigation: %s (in %s ASes)" % (IPNum, ASNum)
            print "--- noisy: %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                allNoisyNum, float(allNoisyNum) * 100 / IPNum, allNoisyASNum, float(allNoisyASNum) * 100 / ASNum)
            print "--- not noisy: %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                notNoisyNum, float(notNoisyNum) * 100 / IPNum, notNoisyASNum, float(notNoisyASNum) * 100 / ASNum)

            print "--- --- probed: %s [%.2f%%]" % (withDirectTrace, float(withDirectTrace) * 100 / notNoisyNum)
            print "--- --- replying: %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                replyingNum, float(replyingNum) * 100 / notNoisyNum, replyingASNum,
                float(replyingASNum) * 100 / notNoisyASNum)
            print "--- --- --- undersampled (<%s occs): %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                undersampled_tresh, undersampledNum, float(undersampledNum) * 100 / replyingNum, undersampledASNum,
                float(undersampledASNum) * 100 / replyingASNum)
            print "--- --- --- not undersampled (>=%s occs): %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                undersampled_tresh, notUndersampledNum, float(notUndersampledNum) * 100 / replyingNum, notUndersampledASNum,
                float(notUndersampledASNum) * 100 / replyingASNum)
            print "--- --- --- --- stable: %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                stableDistanceNum, float(stableDistanceNum) * 100 / notUndersampledNum, stableDistanceASNum,
                float(stableDistanceASNum) * 100 / notUndersampledASNum)
            print "--- --- --- --- fluctuating: %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                fluctuatingDistanceNum, float(fluctuatingDistanceNum) * 100 / notUndersampledNum,
                fluctuatingDistanceASNum,
                float(fluctuatingDistanceASNum) * 100 / notUndersampledASNum)

            print "--- --- --- --- D<T: %s [%.2f%%] (in %s ASes [%.2f%%])" % (
                incFIB1Num, float(incFIB1Num) * 100 / notUndersampledNum, incFIB1ASNum,
                float(incFIB1ASNum) * 100 / notUndersampledASNum)

        except ZeroDivisionError:
            pass

        try:

            sfn.write("Egress points initially under investigation: %s (in %s ASes)\n" % (IPNum, ASNum))
            sfn.write("--- noisy: %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                allNoisyNum, float(allNoisyNum) * 100 / IPNum, allNoisyASNum, float(allNoisyASNum) * 100 / ASNum))
            sfn.write("--- not noisy: %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                notNoisyNum, float(notNoisyNum) * 100 / IPNum, notNoisyASNum, float(notNoisyASNum) * 100 / ASNum))

            sfn.write("--- --- probed: %s [%.2f%%]\n" % (withDirectTrace, float(withDirectTrace) * 100 / notNoisyNum))
            sfn.write("--- --- replying: %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                replyingNum, float(replyingNum) * 100 / notNoisyNum, replyingASNum,
                float(replyingASNum) * 100 / notNoisyASNum))
            sfn.write("--- --- --- undersampled (<%s occs): %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                undersampled_tresh, undersampledNum, float(undersampledNum) * 100 / replyingNum, undersampledASNum,
                float(undersampledASNum) * 100 / replyingASNum))
            sfn.write("--- --- --- not undersampled (>=%s occs): %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                undersampled_tresh, notUndersampledNum, float(notUndersampledNum) * 100 / replyingNum, notUndersampledASNum,
                float(notUndersampledASNum) * 100 / replyingASNum))
            sfn.write("--- --- --- --- stable: %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                stableDistanceNum, float(stableDistanceNum) * 100 / notUndersampledNum, notUndersampledASNum,
                float(stableDistanceASNum) * 100 / notUndersampledASNum))
            sfn.write("--- --- --- --- fluctuating: %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                fluctuatingDistanceNum, float(fluctuatingDistanceNum) * 100 / notUndersampledNum,
                fluctuatingDistanceASNum,
                float(fluctuatingDistanceASNum) * 100 / notUndersampledASNum))

            sfn.write("--- --- --- --- D<T: %s [%.2f%%] (in %s ASes [%.2f%%])\n" % (
                incFIB1Num, float(incFIB1Num) * 100 / notUndersampledNum, incFIB1ASNum,
                float(incFIB1ASNum) * 100 / notUndersampledASNum))

        except ZeroDivisionError:
            return

        # must return some of these lists of CW Egress points...
        return {"notUndersampled": notUndersampled,
                "notNoisy": notNoisy,
                "replying": replying}

    def plotFIBIncScaleM12(self, cwEgressList=None, outFileName=None):
        """
        Plots the distribution of cwep.FIBInconsistencyMetric and cwep.FIBInconsistencyMetric2 together.
.
        """

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        #        if not outFileName:
        #            bpFileName = "%s-big-picture.XXX" % self.nickname
        #        else:
        #            bpFileName = outFileName

        data = defaultdict(list)
        data2 = defaultdict(list)
        for cwep in cwEgressPoints:
            data[cwep.AS].append(cwep.FIBInconsistencyMetric)
            data2[cwep.AS].append(cwep.FIBInconsistencyMetric2)

        # USE TEX (occhio alle label!)
        plt.rc('text', usetex=True)
        plt.rc('font', family='serif')
        #        plt.rc('font', size=20)

        sns.set_style({'font.family': 'serif', 'font.serif': 'Computer Modern'})
        sns.set_context("paper", font_scale=1, rc={"lines.linewidth": 3.0})
        sns.set_style("ticks",
                      {
                          "xtick.direction": "in",
                          "ytick.direction": "in",
                          "ytick.major.size": 20,
                          "ytics.minor.size": 5,
                          "xticks.major.size": 20,
                          "xtick.minor.size": 5
                      }
                      )

        plt.rc('axes', prop_cycle=(cycler('color', ['r', 'r', 'g', 'g', 'b', 'b', 'y', 'y', 'k', 'k', 'm', 'm'])))
        COLS = 2
        ROWS = 4
        f, axes = plt.subplots(ROWS, COLS, figsize=(7, 12))

        for AS in data:
            d = data[AS]
            d2 = data2[AS]
            counter = 0
            for surv in [False, True]:
                for xsc in ["lin", "log"]:
                    for ysc in ["lin", "log"]:

                        col = counter % COLS
                        row = counter / COLS
                        if ysc == "log":
                            ylim = (0.01, 1)
                        else:
                            ylim = (0, 1)

                        if xsc == "log":
                            xlim = (0.05, 1)
                        else:
                            xlim = (0, 1)

                        #                        plotECDF(d, axes[row,col], label="AS"+AS.replace("_", "\\_")+" $D_D < D_T$", xlabel="\\begin{center}Fraction of transit paths\\end{center}", linestyle="solid",  xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        #                        plotECDF(d2, axes[row,col], label="AS"+AS.replace("_", "\\_")+" $D_D \\neq D_T\\\\ OR\\\\ MPLSHOPS_D \\neq MPLSHOPS_T$", xlabel="\\begin{center}Fraction of transit paths\\end{center}", linestyle="dotted",  xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        plotECDF(d, axes[row, col], label="AS" + AS.replace("_", "\\_") + " M1",
                                 xlabel="\\begin{center}Fraction of transit paths\\end{center}", linestyle="solid",
                                 xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        plotECDF(d2, axes[row, col], label="AS" + AS.replace("_", "\\_") + " M2",
                                 xlabel="\\begin{center}Fraction of transit paths\\end{center}", linestyle="dotted",
                                 xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        counter += 1

        plt.tight_layout()
        plt.savefig("%s-INCONSISTENCYSCALE8_M3.pdf" % self.nickname, format="pdf")

    def plotFIBIncScaleM2(self, cwEgressList=None, outFileName=None):
        """
        Plots the distribution of cwep.FIBInconsistencyMetric2.
        """

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        if not outFileName:
            figFileName = "%s-incscaleM2.pdf" % self.nickname

        else:
            figFileName = outFileName

        figFileName2 = "%s-8x.pdf" % figFileName.split(".pdf")[0]

        data = defaultdict(list)

        for cwep in cwEgressPoints:

            if cwep.classification() in [CWEgressPoint.BGPDETOUR, CWEgressPoint.DIFFERENTINGRESS,
                                         CWEgressPoint.MULTIPLEINGRESSES, CWEgressPoint.SPURIOUS1,
                                         CWEgressPoint.SPURIOUS2, CWEgressPoint.SPURIOUS3, CWEgressPoint.SPURIOUS4]:
                continue

            data[cwep.AS].append(cwep.FIBInconsistencyMetric2)

        # USE TEX (occhio alle label!)
        plt.rc('text', usetex=True)
        plt.rc('font', family='serif')
        #        plt.rc('font', size=20)

        sns.set_style({'font.family': 'serif', 'font.serif': 'Computer Modern'})
        sns.set_context("paper", font_scale=1, rc={"lines.linewidth": 3.0})
        sns.set_style("ticks",
                      {
                          "xtick.direction": "in",
                          "ytick.direction": "in",
                          "ytick.major.size": 20,
                          "ytics.minor.size": 5,
                          "xticks.major.size": 20,
                          "xtick.minor.size": 5
                      }
                      )
        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        colormap = plt.cm.gist_ncar
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, len(data))])

        COLS = 2
        ROWS = 4
        f, axes = plt.subplots(ROWS, COLS, figsize=(7, 12))

        for AS in data:
            d = data[AS]
            counter = 0
            for surv in [False, True]:
                for xsc in ["lin", "log"]:
                    for ysc in ["lin", "log"]:

                        col = counter % COLS
                        row = counter / COLS
                        if ysc == "log":
                            ylim = (0.01, 1)
                        else:
                            ylim = (0, 1)

                        if xsc == "log":
                            xlim = (0.05, 1)
                        else:
                            xlim = (0, 1)

                        plotECDF(d, axes[row, col], label="AS" + AS.replace("_", "\\_"),
                                 xlabel="\\begin{center}Fraction of transit paths for which \\\\ $D_T \\neq D_D$ OR $MPLSHOPS_T \\neq MPLSHOPS_D$\\end{center}",
                                 xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        counter += 1

        plt.tight_layout()
        plt.savefig(figFileName2, format="pdf")

        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        f, ax = plt.subplots(figsize=(5, 2.25))
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, 16)])
        for AS in data:
            d = data[AS]

            plotECDF(d, ax, label="AS" + AS.replace("_", "\\_"),
                     xlabel="\\begin{center}Fraction of transit paths for which \\\\ $D_T \\neq D_D$ OR $MPLSHOPS_T \\neq MPLSHOPS_D$\\end{center}",
                     xscale="lin", yscale="log", survival=surv, xlim=(0, 1), ylim=ylim)

        plt.legend(ncol=2, loc='center left', bbox_to_anchor=(1.05, 0.5), fontsize=6)
        plt.subplots_adjust(right=0.6)
        plt.tight_layout()
        plt.savefig(figFileName, format="pdf")

    def plotFIBIncScaleM1(self, cwEgressList=None, outFileName=None):
        """
        Plots the distribution of cwep.FIBInconsistencyMetric.
        """

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        if not outFileName:
            figFileName = "%s-incscaleM1.pdf" % self.nickname

        else:
            figFileName = outFileName

        figFileName2 = "%s-8x.pdf" % figFileName.split(".pdf")[0]

        data = defaultdict(list)

        for cwep in cwEgressPoints:

            if cwep.classification() in [CWEgressPoint.BGPDETOUR, CWEgressPoint.DIFFERENTINGRESS,
                                         CWEgressPoint.MULTIPLEINGRESSES, CWEgressPoint.SPURIOUS1,
                                         CWEgressPoint.SPURIOUS2, CWEgressPoint.SPURIOUS3, CWEgressPoint.SPURIOUS4]:
                continue
            #            if cwep.classification() in [CWEgressPoint.BGPDETOUR, CWEgressPoint.DIFFERENTINGRESS, CWEgressPoint.MULTIPLEINGRESSES]:
            #                continue

            data[cwep.AS].append(cwep.FIBInconsistencyMetric)

        # USE TEX (occhio alle label!)
        plt.rc('text', usetex=True)
        plt.rc('font', family='serif')
        #        plt.rc('font', size=20)

        sns.set_style({'font.family': 'serif', 'font.serif': 'Computer Modern'})
        sns.set_context("paper", font_scale=1, rc={"lines.linewidth": 3.0})
        sns.set_style("ticks",
                      {
                          "xtick.direction": "in",
                          "ytick.direction": "in",
                          "ytick.major.size": 20,
                          "ytics.minor.size": 5,
                          "xticks.major.size": 20,
                          "xtick.minor.size": 5
                      }
                      )
        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        colormap = plt.cm.gist_ncar
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, len(data))])

        COLS = 2
        ROWS = 4
        f, axes = plt.subplots(ROWS, COLS, figsize=(7, 12))

        for AS in data:
            d = data[AS]
            counter = 0
            for surv in [False, True]:
                for xsc in ["lin", "log"]:
                    for ysc in ["lin", "log"]:

                        col = counter % COLS
                        row = counter / COLS
                        if ysc == "log":
                            ylim = (0.01, 1)
                        else:
                            ylim = (0, 1)

                        if xsc == "log":
                            xlim = (0.05, 1)
                        else:
                            xlim = (0, 1)

                        plotECDF(d, axes[row, col], label="AS" + AS.replace("_", "\\_"),
                                 xlabel="\\begin{center}Fraction of transit paths\\\\longer than direct path\\end{center}",
                                 xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        counter += 1

        plt.tight_layout()
        plt.savefig(figFileName2, format="pdf")

        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        f, ax = plt.subplots(figsize=(5, 2.25))
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, 16)])
        for AS in data:
            d = data[AS]
            plotECDF(d, ax, label="AS" + AS.replace("_", "\\_"),
                     xlabel="\\begin{center}Fraction of transit paths\\\\longer than direct path\\end{center}",
                     xscale="lin", yscale="log", survival=True, xlim=(0, 1), ylim=(0.01, 1))
        plt.legend(ncol=2, loc='center left', bbox_to_anchor=(1.05, 0.5), fontsize=6)
        plt.subplots_adjust(right=0.6)
        plt.tight_layout()
        plt.savefig(figFileName, format="pdf")

    def plotFIBIncScaleM3(self, cwEgressList=None, outFileName=None):
        """
        Plots the distribution of cwep.FIBInconsistencyMetric3.
        """

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        if not outFileName:
            figFileName = "%s-incscaleM3.pdf" % self.nickname

        else:
            figFileName = outFileName

        figFileName2 = "%s-8x.pdf" % figFileName.split(".pdf")[0]

        data = defaultdict(list)

        for cwep in cwEgressPoints:

            if cwep.classification() in [CWEgressPoint.BGPDETOUR,
                                         CWEgressPoint.DIFFERENTINGRESS,
                                         CWEgressPoint.MULTIPLEINGRESSES,
                                         CWEgressPoint.SPURIOUS1,
                                         CWEgressPoint.SPURIOUS2,
                                         CWEgressPoint.SPURIOUS3,
                                         CWEgressPoint.SPURIOUS4]:
                continue
            #            if cwep.classification() in [CWEgressPoint.BGPDETOUR, CWEgressPoint.DIFFERENTINGRESS, CWEgressPoint.MULTIPLEINGRESSES]:
            #                continue

            data[cwep.AS].append(cwep.FIBInconsistencyMetric3)

        # USE TEX (occhio alle label!)
        plt.rc('text', usetex=True)
        plt.rc('font', family='serif')
        #        plt.rc('font', size=20)

        sns.set_style({'font.family': 'serif', 'font.serif': 'Computer Modern'})
        sns.set_context("paper", font_scale=1, rc={"lines.linewidth": 3.0})
        sns.set_style("ticks",
                      {
                          "xtick.direction": "in",
                          "ytick.direction": "in",
                          "ytick.major.size": 20,
                          "ytics.minor.size": 5,
                          "xticks.major.size": 20,
                          "xtick.minor.size": 5
                      }
                      )
        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        colormap = plt.cm.gist_ncar
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, len(data))])

        COLS = 2
        ROWS = 4
        f, axes = plt.subplots(ROWS, COLS, figsize=(7, 12))

        for AS in data:
            d = data[AS]
            counter = 0
            for surv in [False, True]:
                for xsc in ["lin", "log"]:
                    for ysc in ["lin", "log"]:

                        col = counter % COLS
                        row = counter / COLS
                        if ysc == "log":
                            ylim = (0.01, 1)
                        else:
                            ylim = (0, 1)

                        if xsc == "log":
                            xlim = (0.05, 1)
                        else:
                            xlim = (0, 1)

                        plotECDF(d, axes[row, col], label="AS" + AS.replace("_", "\\_"),
                                 xlabel="\\begin{center}Fraction of transit paths\\\\with 2 MPLS tunnels\\\\when direct path has only 1 or 0 tunnels\\end{center}",
                                 xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        counter += 1

        plt.tight_layout()
        plt.savefig(figFileName2, format="pdf")

        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        f, ax = plt.subplots(figsize=(5, 2.25))
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, 16)])
        for AS in data:
            d = data[AS]
            plotECDF(d, ax, label="AS" + AS.replace("_", "\\_"),
                     xlabel="\\begin{center}Fraction of transit paths\\\\with 2 MPLS tunnels\\\\when direct path has only 1 or 0 tunnels\\end{center}",
                     xscale="lin", yscale="log", survival=True, xlim=(0, 1), ylim=(0.01, 1))
        plt.legend(ncol=2, loc='center left', bbox_to_anchor=(1.05, 0.5), fontsize=6)
        plt.subplots_adjust(right=0.6)
        plt.tight_layout()
        plt.savefig(figFileName, format="pdf")

    def plotFIBIncScaleM4(self, cwEgressList=None, outFileName=None):
        """
        Plots the distribution of cwep.FIBInconsistencyMetric4.
        """

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        if not outFileName:
            figFileName = "%s-incscaleM4.pdf" % self.nickname

        else:
            figFileName = outFileName

        figFileName2 = "%s-8x.pdf" % figFileName.split(".pdf")[0]

        data = defaultdict(list)

        for cwep in cwEgressPoints:

            if cwep.classification() in [CWEgressPoint.BGPDETOUR,
                                         CWEgressPoint.DIFFERENTINGRESS,
                                         CWEgressPoint.MULTIPLEINGRESSES,
                                         CWEgressPoint.SPURIOUS1,
                                         CWEgressPoint.SPURIOUS2,
                                         CWEgressPoint.SPURIOUS3,
                                         CWEgressPoint.SPURIOUS4]:
                continue
            #            if cwep.classification() in [CWEgressPoint.BGPDETOUR, CWEgressPoint.DIFFERENTINGRESS, CWEgressPoint.MULTIPLEINGRESSES]:
            #                continue

            data[cwep.AS].append(cwep.FIBInconsistencyMetric4)

        # USE TEX (occhio alle label!)
        plt.rc('text', usetex=True)
        plt.rc('font', family='serif')
        #        plt.rc('font', size=20)

        sns.set_style({'font.family': 'serif', 'font.serif': 'Computer Modern'})
        sns.set_context("paper", font_scale=1, rc={"lines.linewidth": 3.0})
        sns.set_style("ticks",
                      {
                          "xtick.direction": "in",
                          "ytick.direction": "in",
                          "ytick.major.size": 20,
                          "ytics.minor.size": 5,
                          "xticks.major.size": 20,
                          "xtick.minor.size": 5
                      }
                      )
        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        colormap = plt.cm.gist_ncar
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, len(data))])

        COLS = 2
        ROWS = 4
        f, axes = plt.subplots(ROWS, COLS, figsize=(7, 12))

        for AS in data:
            d = data[AS]
            counter = 0
            for surv in [False, True]:
                for xsc in ["lin", "log"]:
                    for ysc in ["lin", "log"]:

                        col = counter % COLS
                        row = counter / COLS
                        if ysc == "log":
                            ylim = (0.01, 1)
                        else:
                            ylim = (0, 1)

                        if xsc == "log":
                            xlim = (0.05, 1)
                        else:
                            xlim = (0, 1)

                        plotECDF(d, axes[row, col], label="AS" + AS.replace("_", "\\_"),
                                 xlabel="\\begin{center}Fraction of transit paths\\\\with different length OR with 2 MPLS tunnels\\\\when direct path has only 1 or 0 tunnels\\end{center}",
                                 xscale=xsc, yscale=ysc, survival=surv, xlim=xlim, ylim=ylim)
                        counter += 1

        plt.tight_layout()
        plt.savefig(figFileName2, format="pdf")

        # plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
        f, ax = plt.subplots(figsize=(5, 2.25))
        plt.gca().set_color_cycle([colormap(i) for i in np.linspace(0, 0.9, 16)])
        for AS in data:
            d = data[AS]
            plotECDF(d, ax, label="AS" + AS.replace("_", "\\_"),
                     xlabel="\\begin{center}Fraction of transit paths\\\\with different length OR with 2 MPLS tunnels\\\\when direct path has only 1 or 0 tunnels\\end{center}",
                     xscale="lin", yscale="log", survival=True, xlim=(0, 1), ylim=(0.01, 1))
        plt.legend(ncol=2, loc='center left', bbox_to_anchor=(1.05, 0.5), fontsize=6)
        plt.subplots_adjust(right=0.6)
        plt.tight_layout()
        plt.savefig(figFileName, format="pdf")

    def writeCWEgressBigPictureReport(self, cwEgressList=None, outFileName=None):

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        if not outFileName:
            bpFileName = "%s-big-picture.csv" % self.nickname
        else:
            bpFileName = outFileName

        ASList = [x.AS for x in cwEgressPoints]
        ASCounter = Counter(ASList)

        IPList = [x.ipAddress for x in cwEgressPoints]
        IPCounter = Counter(IPList)

        AStoIP = {}  # needed mainly to improve performance
        for AS in ASCounter:
            AStoIP[AS] = list(set([x.ipAddress for x in cwEgressPoints if x.AS == AS]))

        bpf = open(bpFileName, 'w')  # big-picture file

        # write header
        bpf.write(";".join([CWEgressPoint.toLineHeader(), CWEgressPoint.toLine2Header(), "\n"]))

        # cycle over ASes and egress points
        for AS in sorted(ASCounter.keys(), key=lambda x: ASCounter[x], reverse=True):
            for ip in sorted(AStoIP[AS], key=lambda x: IPCounter[x], reverse=True):

                w = cwEgressPointsByIP[ip]
                if w.allNoisy:
                    # pprint(w.__dict__.keys())
                    continue

                bpf.write(";".join([w.toLine(), w.toLine2(), "\n"]))
        bpf.close()

    def writeCWEgressDetails(self, referenceCampaign=None, cwEgressList=None, outFileName=None, tracesToPrint=5):
        """
        Generates NICKNAME-details.txt (and similar).
        """

        if not cwEgressList:
            cwEgressPoints = self.CWEgressPoints
            cwEgressPointsByIP = self.CWEgressPointsByIP
        else:
            cwEgressPoints = cwEgressList
            cwEgressPointsByIP = {x.ipAddress: x for x in cwEgressPoints}

        if not outFileName:
            detailsFileName = "%s-details.txt" % self.nickname
        else:
            detailsFileName = outFileName

        ASList = [x.AS for x in cwEgressPoints]
        ASCounter = Counter(ASList)

        IPList = [x.ipAddress for x in cwEgressPoints]
        IPCounter = Counter(IPList)

        AStoIP = {}  # needed mainly to improve performance
        for AS in ASCounter:
            AStoIP[AS] = list(set([x.ipAddress for x in cwEgressPoints if x.AS == AS]))

        # PRINT DETAILS
        s = WhoisServer("riswhois.ripe.net")
        df = open(detailsFileName, 'w')
        for AS in sorted(ASCounter.keys(), key=lambda x: ASCounter[x], reverse=True):
            df.write("* AS%s\t%s (%s)\n" % (AS, s.asLookup(AS), len(AStoIP[AS])))
            for ip in sorted(AStoIP[AS], key=lambda x: cwEgressPointsByIP[x].occ, reverse=True):
                df.write(
                    "+ {ip} {revdns} ({num})\n".format(ip=ip, revdns=reverseDNS(ip), num=cwEgressPointsByIP[ip].occ))
                i = 0
                tosample = min(tracesToPrint, len(cwEgressPointsByIP[ip].originatingTraces))
                random.seed(a=ip)
                for x in random.sample(cwEgressPointsByIP[ip].originatingTraces, tosample):
                    i += 1
                    df.write("T{i} {trace}\n".format(i=i, trace=x))
                if referenceCampaign and ip in referenceCampaign.tracesByDestination:
                    df.write("D1 {trace}\n".format(trace=referenceCampaign.tracesByDestination[ip]))
                df.write("\n")
            df.write("\n")
        df.close()

    def getEgressReportXXX(self, referenceCampaign=None):
        """
        DEPRECATED!

        Focuses just on provider AS for now

        null traces filtered out upstream
        ip2as mapping (and related) done upstream

        """

        # first identify ep
        ASInfoList = []  # contains not only the egress point information, but also that related to the AS it belongs to (ingress, and metrics)

        for t in self.traces:
            if t.providerAS == None or t.providerAS == t.destinationAS:
                continue

            try:
                asOccurrence = t.ASInfo[t.providerAS]  # one obj per trace, at most.
                ASInfoList.append(asOccurrence)
            except Exception, e:
                print "exception in getEgressReportXXX"
                print e.message
                raw_input()

        ASInfoList_noisyEp = [x for x in ASInfoList if x.egressPoint.isNoisy]
        ASInfoList = list(set(ASInfoList).difference(set(ASInfoList_noisyEp)))  # remove noisy egress points

        notNoisyByIP = defaultdict(list)
        for x in ASInfoList:
            notNoisyByIP[x.egressPoint.ipAddress].append(x)

        ASList = [x.AS for x in ASInfoList]
        ASCounter = Counter(ASList)

        IPList = [x.egressPoint.ipAddress for x in ASInfoList]
        IPCounter = Counter(IPList)

        AStoIP = {}  # nedded mainly to improve performance
        for AS in ASCounter:
            AStoIP[AS] = list(set([x.egressPoint.ipAddress for x in ASInfoList if x.AS == AS]))

        # DISTANCE
        infoBase1c = {}  # AS --> ip --> distance distribution
        for AS in ASCounter.keys():
            infoBase1c[AS] = {}
            for ip in AStoIP[AS]:
                infoBase1c[AS][ip] = Counter([x.egressPoint.hopNum + 1 for x in notNoisyByIP[ip]])

        # MPLS HOPS
        infoBase2c = {}  # AS --> ip --> MPLS hops distribution (i.e. number of hops exposing MPLS label in the AS)
        for AS in ASCounter.keys():
            infoBase2c[AS] = {}
            for ip in AStoIP[AS]:
                infoBase2c[AS][ip] = Counter([x.mplsHops for x in notNoisyByIP[ip]])

        # AS LENGTH
        infoBase3c = {}  # AS --> ip --> AS length distribution (i.e. number of hops in the AS)
        for AS in ASCounter.keys():
            infoBase3c[AS] = {}
            for ip in AStoIP[AS]:
                infoBase3c[AS][ip] = Counter([x.ASLength for x in notNoisyByIP[ip]])

        # INGRESS POINTS
        infoBase4c = {}  # AS --> ip --> List of ingress points (for this egress point)
        for AS in ASCounter.keys():
            infoBase4c[AS] = {}
            for ip in AStoIP[AS]:
                infoBase4c[AS][ip] = Counter([x.ingressPoint.ipAddress for x in notNoisyByIP[ip]])

        # REFERENCE CAMPAIGN
        directDistance = {}
        for t in referenceCampaign.traces:
            directDistance[t.destination] = t.destDistance

        #        def compare(DD, TDs):
        #
        #            if len(TDs) > 1:
        #                return {
        #                        "DD = maxTD": DD == max(TDs),
        #                        "DD < maxTD": DD < max(TDs),
        #                        "DD > maxTD": DD > max(TDs),
        #                        "DD = minTD": DD == min(TDs),
        #                        "DD < minTD": DD < min(TDs),
        #                        "DD < minTD": DD > min(TDs)
        #                        }
        #            else:
        #                return {
        #                        "DD = TD": DD == TDs[0],
        #                        "DD < TD": DD < TDs[0],
        #                        "DD > TD": DD > TDs[0]
        #                        }

        def compareDistance(dd, tds):
            """
            compare direct distance towards an egress point against (the maximum) if transit distances.
            returns "?" if direct distance is not available.
            """
            ret = "?" if dd == 0 else "<" if dd < max(tds) else "=" if dd == max(tds) else ">"
            return ret

        def compare2(dd, tds):
            """
            Same as compareDistance, but does not consider dd=0 as a special value.
            It is used for comparintg other metrics (e.g., ASHops, MPLS hops)
            """
            ret = "<" if dd < max(tds) else "=" if dd == max(tds) else ">"
            # if dd>max(tds)
            return ret
        azz = defaultdict(dict)

        bpFileName = "%s-big-picture.csv" % self.nickname
        detailsFileName = "%s-details.txt" % self.nickname

        bpf = open(bpFileName, 'w')  # big-picture file

        # write header
        bpf.write(
            "{AS};{ip};{fqdn};{occ};{tdiststab};{tdist};{tdistocc};{ddist};{d_t_dist};{d_t_aspath};{d_t_ingress};{d_t_ashops};{d_t_mplshops}\n".format( \
                AS="ASN",
                ip="IP",
                occ="Occurrences",
                fqdn="reverseDNS", \
 \
                d_t_dist="D?T_Distance",
                d_t_aspath="D?T_ASPath",
                d_t_ingress="D?T_IngressPoint",
                d_t_ashops="D?T_ASHops",
                d_t_mplshops="D?T_MPLSHops", \
 \
                tdiststab="Transit Distance Stability",
                tdistocc="Transit Distance Occurrences",
                tdist="Transit Distance",
                ddist="Direct Distance"
            ))

        # cycle over ASes and egress points
        for AS in sorted(ASCounter.keys(), key=lambda x: ASCounter[x], reverse=True):
            for ip in sorted(AStoIP[AS], key=lambda x: IPCounter[x], reverse=True):
                # tmp variables just to have easier codintions below
                transitASSeqs = set(
                    [tuple(x.originatingTrace.ASSequence[:x.originatingTrace.ASSequence.index(AS) + 1]) for x in
                     notNoisyByIP[ip]])
                directASSeq = tuple(referenceCampaign.tracesByDestination[ip].ASSequence)
                transitIngressPoints = infoBase4c[AS][ip].keys()
                directIngressPoint = referenceCampaign.tracesByDestination[ip].ASInfo[
                    AS].ingressPoint.ipAddress if AS in referenceCampaign.tracesByDestination[ip].ASInfo else '?'

                # w is a CAMPAIGN-WISE egress point
                w = {"AS": AS,
                     "IP": ip,
                     "Occ": len(notNoisyByIP[ip]),
                     "TransitDistanceStability": 'S' if len(infoBase1c[AS][ip].keys()) == 1 else 'F',
                     "TransitDistance": infoBase1c[AS][ip].keys(),
                     "TransitDistanceOcc": infoBase1c[AS][ip].values(),
                     "TransitMplsHops": infoBase2c[AS][ip].keys(),
                     "TransitMplsHopsOcc": infoBase2c[AS][ip].values(),
                     "TransitASHops": infoBase3c[AS][ip].keys(),
                     "TransitASHopsOcc": infoBase3c[AS][ip].values(),
                     "TransitIngressPointsNum": len(transitIngressPoints),
                     "TransitIngressPoints": transitIngressPoints,
                     "TransitIngressPointsOcc": infoBase4c[AS][ip].values(),
                     "DirectDistance": referenceCampaign.tracesByDestination[ip].destDistance,
                     "D?T_Distance": compareDistance(referenceCampaign.tracesByDestination[ip].destDistance,
                                                     infoBase1c[AS][ip].keys()),
                     "TransitASSeqs": set(
                         [tuple(x.originatingTrace.ASSequence[:x.originatingTrace.ASSequence.index(AS) + 1]) for x in
                          notNoisyByIP[ip]]),
                     "DirectASSeq": tuple(referenceCampaign.tracesByDestination[ip].ASSequence),
                     # "SameASPath": tuple(referenceCampaign.tracesByDestination[ip].ASSequence) in set([tuple(x.originatingTrace.ASSequence[:x.originatingTrace.ASSequence.index(AS)+1]) for x in notNoisyByIP[ip]]),
                     "D?T_ASPath": 'S' if (len(transitASSeqs) == 1 and directASSeq == list(transitASSeqs)[0]) else \
                         'I' if directASSeq in transitASSeqs else \
                             '?' if (referenceCampaign.tracesByDestination[ip].destDistance == 0 and True in [
                                 x[:len(directASSeq)] == directASSeq for x in transitASSeqs]) else \
                                 'D',
                     "DirectASHops": referenceCampaign.tracesByDestination[ip].ASInfo[AS].ASLength if AS in
                                                                                                      referenceCampaign.tracesByDestination[
                                                                                                          ip].ASInfo else '?',
                     "DirectMplsHops": referenceCampaign.tracesByDestination[ip].ASInfo[AS].mplsHops if AS in
                                                                                                        referenceCampaign.tracesByDestination[
                                                                                                            ip].ASInfo else '?',
                     "DirectIngressPoint": referenceCampaign.tracesByDestination[ip].ASInfo[
                         AS].ingressPoint.ipAddress if AS in referenceCampaign.tracesByDestination[ip].ASInfo else '?',
                     "D?T_IngressPoint": '?' if directIngressPoint == '?' else \
                         'S' if (len(transitIngressPoints) == 1 and transitIngressPoints[0] == directIngressPoint) else \
                             'I' if directIngressPoint in transitIngressPoints else \
                                 'D',
                     "D?T_MplsHops": compare2(referenceCampaign.tracesByDestination[ip].ASInfo[AS].mplsHops,
                                              infoBase2c[AS][ip].keys()) if AS in referenceCampaign.tracesByDestination[
                         ip].ASInfo else '?',
                     "D?T_ASHops": compare2(referenceCampaign.tracesByDestination[ip].ASInfo[AS].ASLength,
                                            infoBase3c[AS][ip].keys()) if AS in referenceCampaign.tracesByDestination[
                         ip].ASInfo else '?'

                     }

                bpf.write(
                    "{AS};{ip};{fqdn};{occ};{tdiststab};{tdist};{tdistocc};{ddist};{d_t_dist};{d_t_aspath};{d_t_ingress};{d_t_ashops};{d_t_mplshops}\n".format(
                        AS=w["AS"],
                        ip=w["IP"],
                        fqdn=reverseDNS(w["IP"]),
                        occ=w["Occ"], \
 \
                        d_t_dist=w["D?T_Distance"],
                        d_t_aspath=w["D?T_ASPath"],
                        d_t_ingress=w["D?T_IngressPoint"],
                        d_t_ashops=w["D?T_ASHops"],
                        d_t_mplshops=w["D?T_MplsHops"], \
 \
                        tdiststab=w["TransitDistanceStability"],
                        tdistocc=w["TransitDistanceOcc"],
                        tdist=w["TransitDistance"],
                        ddist=w["DirectDistance"]
                    ))

        bpf.close()

        # raw_input()

        # CANDIDATES INC FIB

        #                if w["DirectDistance"] > 0 and w["D?T_IngressPoint"] in ['?', 'I', 'S'] and w["D?T_IngressPoint"] in ['S', 'I'] and w['D?T_ASPath'] in ['S', 'I'] and w["D?T_Distance"] == '<':
        #                    potentialINCFIB +=1
        #                    print "D", referenceCampaign.tracesByDestination[ip]
        #                    print "T", notNoisyByIP[ip][0].originatingTrace
        #                    #pprint(referenceCampaign.tracesByDestination[ip].__dict__)
        #                    pprint(w)
        #                    raw_input()
        #

        # D > T
        #                if w["D?T_Distance"] == '>': #and w["AS"] in ['101', '2914', '2200', '2497']:
        #                    Dlonger += 1
        #                    DlongerList.append(AS)
        ##                    print "D", referenceCampaign.tracesByDestination[ip]
        ##                    print "T", notNoisyByIP[ip][0].originatingTrace
        ##                    #pprint(referenceCampaign.tracesByDestination[ip].__dict__)
        ##                    pprint(w)
        ##                    raw_input()

        #        print "potential INCFIB", potentialINCFIB
        #        print "D longer than T", Dlonger
        #        print Counter(DlongerList)
        #
        #        raw_input()
        #        return
        #
        s = WhoisServer("riswhois.ripe.net")
        # PRINT!

        df = open(detailsFileName, 'w')

        for AS in sorted(ASCounter.keys(), key=lambda x: ASCounter[x], reverse=True):
            # print "\nAS%s\t%s (%s)" % (AS, s.asLookup(AS), len(set([x.egressPoint.ipAddress for x in ASInfoList if x.AS == AS])))
            df.write("* AS%s\t%s (%s)\n" % (
                AS, s.asLookup(AS), len(set([x.egressPoint.ipAddress for x in ASInfoList if x.AS == AS]))))
            # for ip in sorted(AStoIP[AS], key=lambda x: len(AStoIP[AS][x]), reverse=True):
            for ip in sorted(AStoIP[AS], key=lambda x: IPCounter[x], reverse=True):
                df.write("+ {ip} {revdns} ({num})\n".format(ip=ip, revdns=reverseDNS(ip), num=IPCounter[ip]))
                i = 0
                tosample = min(5, len(notNoisyByIP[ip]))
                random.seed(a=ip)
                for x in random.sample(notNoisyByIP[ip], tosample):
                    # for x in notNoisyByIP[ip]:
                    # if i == 10:
                    #    break
                    i += 1
                    df.write("T{i} {trace}\n".format(i=i, trace=x.originatingTrace))
                    # print "T{i} {trace}\n".format(i=i, trace=x.originatingTrace)
                # print "D1 {trace}".format(trace=referenceCampaign.tracesByDestination[ip])
                df.write("D1 {trace}\n".format(trace=referenceCampaign.tracesByDestination[ip]))
                df.write("\n")

            df.write("\n")
        df.close()

    def printEgressReport2(self, mapper):
        """
        Focuses on provider AS for now
        """

        # first identify ep
        epOfInterest = []
        noisyFirstEgressCount = 0

        for t in self.traces:

            if t.ASHops == {}:
                t.IP2ASMappingAndRelated(
                    mapper)  # do IP2AS mapping on the whole trace - populates t.ASHops that is needed for tracing egress hops
            if t.hops == {}:
                continue

            # look for the egress point of the provider AS
            try:
                if t.ASSequence[0] != t.sourceAS:
                    providerAS = t.ASSequence[0]
                else:
                    providerAS = t.ASSequence[1]
            except:
                providerAS = None
            if providerAS == None:
                continue

            for ep in t.egressPoints:
                if ep.AS == providerAS:  # provider's egress point
                    if ep.isNoisy:
                        noisyFirstEgressCount += 1  # exclude noisy egress points
                    else:
                        epOfInterest.append(ep)

        infoBase = {}
        epIPList = []
        epASList = []
        epIPASList = []
        # how may eps in the campaign?
        # which provider do they belong to?
        # do they appear at the same distance?

        for ep in epOfInterest:
            if ep.AS in infoBase:
                if ep.ipAddress in infoBase[ep.AS]:
                    infoBase[ep.AS][ep.ipAddress].update([ep.hopNum + 1])
                else:
                    infoBase[ep.AS][ep.ipAddress] = Counter([ep.hopNum + 1])
            else:
                infoBase[ep.AS] = {}
                infoBase[ep.AS][ep.ipAddress] = Counter([ep.hopNum + 1])

            epIPList.append(ep.ipAddress)
            epASList.append(ep.AS)
            epIPASList.append((ep.AS, ep.ipAddress))

        epASListCounter = Counter(epASList)
        epASNum = len(epASListCounter.keys())

        epIPListCounter = Counter(epIPList)
        epNum = len(epIPListCounter.keys())

        epIPASListCounter = Counter(epIPASList)
        epIPASNum = len(epIPASListCounter.keys())

        fluctuatingDistanceEpList = []
        stableDistanceEpList = []
        for AS in infoBase:
            for ip in infoBase[AS]:
                if len(infoBase[AS][ip].keys()) > 1:
                    fluctuatingDistanceEpList.append((AS, ip, infoBase[AS][ip].keys()))
                else:
                    stableDistanceEpList.append((AS, ip, infoBase[AS][ip].keys()))

        fluctuatingDistanceEpListNum = len(fluctuatingDistanceEpList)
        stableDistanceEpListNum = len(stableDistanceEpList)

        print "\n::EGRESS REPORT (summary)::"
        print "Number of noisyFirstEgress Traces:\t%s" % noisyFirstEgressCount
        print "Number of egress IPs:\t\t\t%s" % epNum
        print "--- with fluctuating distance\t\t%s (%.2f %%)" % (
            fluctuatingDistanceEpListNum, float(fluctuatingDistanceEpListNum) * 100 / epNum)
        print "--- with stable distance\t\t%s (%.2f %%)" % (
            stableDistanceEpListNum, float(stableDistanceEpListNum) * 100 / epNum)
        print "Number of egress ASes:\t\t\t%s" % epASNum

        s = WhoisServer("riswhois.ripe.net")
        print "\n::EGRESS ASes::"
        for AS in sorted(epASListCounter, key=lambda x: epASListCounter[x], reverse=True):
            print "%s\t%s\t%s" % (AS, epASListCounter[AS], s.asLookup(AS))

        #        print "\n::Egress IPs"
        #        for ep in sorted(epIPASListCounter, key=lambda x: epIPASListCounter[x], reverse=True):
        #            print "%s\t%s\t%s" % (ep[1], ep[0], epIPASListCounter[ep])

        print "\n::DISTANCE DISTRIBUTION (per egress point -- only those with fluctuating distance)::"
        for AS in infoBase:
            for ip in infoBase[AS]:
                if len(infoBase[AS][ip].keys()) > 1:
                    distances = infoBase[AS][ip].keys()
                    occurrences = infoBase[AS][ip].values()
                    print "%s\t%s\t%s\t%s" % (AS, ip, distances, occurrences)
                    # print "%s\t%s\t%s" % (ip, distances, map(lambda x: float(x)/sum(occurrences), occurrences))
                    print "%s\t%s\t%s\t%s" % (AS, ip, distances, ["{0:0.2f}".format(i) for i in
                                                                  map(lambda x: float(x) / sum(occurrences),
                                                                      occurrences)])
                    print ""

        if False:
            print "\n::EGRESS POINTS::\n"
            #        for ip in list(set(epIPList)):
            #            print "%s\t%s" % (ip, reverseDNS(ip))

            for ip in sorted(epIPListCounter, key=lambda x: epIPListCounter[x], reverse=True):
                print "%s\t%s\t%s" % (ip, epIPListCounter[ip], reverseDNS(ip))

    def printEgressReport(self, mapper):
        """
        Replaced by printEgressReport2
        """
        egressIPList = []
        egressASList = []
        neighbourIPList = []
        neighbourASList = []
        egressIP_DistanceList = []
        egressIP_Distance_neighbourASList = []
        egressIP_Distance_destinationASList = []

        noisyFirstEgressCount = 0

        distanceInfo = {}
        distanceNeighbourASInfo = {}
        distanceDestinationASInfo = {}
        distanceMplsInfo = {}

        for t in self.traces:  # for all the traces in this campaign
            if t.ASHops == {}:
                t.IP2ASMappingAndRelated(
                    mapper)  # do IP2AS mapping on the whole trace - populates t.ASHops that is needed for tracing egress hops
            if t.hops == {}:
                continue
            if t.noisyFirstEgress == True:
                noisyFirstEgressCount += 1
                continue

            egressHop = t.getFirstEgressHop()
            if egressHop != None:

                egressIP = t.hops[egressHop][0]
                egressAS = t.ASHops[egressHop][0]

                neighbourIP = t.hops[egressHop + 1][0]
                neighbourAS = t.ASHops[egressHop + 1][0]

                distance = egressHop + 1

                egressIPList.append(egressIP)
                egressASList.append(egressAS)
                neighbourIPList.append(neighbourIP)
                neighbourASList.append(neighbourAS)
                egressIP_DistanceList.append((egressIP, distance))
                egressIP_Distance_neighbourASList.append((egressIP, distance, neighbourAS))
                egressIP_Distance_destinationASList.append((egressIP, distance, t.destinationAS))

                mplsHopsBeforeEgress = t.mplsHopsBefore(
                    egressHop)  # how many hops expose MPLS labels up to the egress hop

                # distanceInfo
                if egressIP in distanceInfo:
                    distanceInfo[egressIP].update([distance])
                else:
                    distanceInfo[egressIP] = Counter([distance])

                # distanceNeighbourASInfo
                if egressIP in distanceNeighbourASInfo:
                    distanceNeighbourASInfo[egressIP].update([(distance, neighbourAS)])
                else:
                    distanceNeighbourASInfo[egressIP] = Counter([(distance, neighbourAS)])

                # distanceDestinationASInfo
                if egressIP in distanceDestinationASInfo:
                    distanceDestinationASInfo[egressIP].update([(distance, t.destinationAS)])
                else:
                    distanceDestinationASInfo[egressIP] = Counter([(distance, t.destinationAS)])

                # distanceMPLSInfo
                if egressIP in distanceMplsInfo:
                    distanceMplsInfo[egressIP].update([(distance, mplsHopsBeforeEgress)])
                else:
                    distanceMplsInfo[egressIP] = Counter([(distance, mplsHopsBeforeEgress)])

        egressIPCounter = Counter(egressIPList)
        egressASCounter = Counter(egressASList)
        neighbourIPCounter = Counter(neighbourIPList)
        neighbourASCounter = Counter(neighbourASList)
        egressIP_DistanceCounter = Counter(egressIP_DistanceList)
        egressIP_Distance_neighbourASCounter = Counter(egressIP_Distance_neighbourASList)
        egressIP_Distance_destinationASCounter = Counter(egressIP_Distance_destinationASList)

        #
        egressIPsWithFluctuatingDistance = [ip for ip in distanceInfo if
                                            len(distanceInfo[ip].keys()) > 1]  # egressIPs seen at different distances
        egressIPsWithStableDistance = [ip for ip in distanceInfo if
                                       len(distanceInfo[ip].keys()) == 1]  # egressIPs seen always at the same distance
        egressIPsWithFluctuatingDistanceNum = len([ip for ip in distanceInfo if len(
            distanceInfo[ip].keys()) > 1])  # number of egressIPs seen at different distances
        egressIPsWithStableDistanceNum = len([ip for ip in distanceInfo if len(
            distanceInfo[ip].keys()) == 1])  # number of egressIPs seen always at the same distance

        print "\n::EGRESS REPORT (summary)::"
        print "Number of noisyFirstEgress Traces:\t%s" % noisyFirstEgressCount
        print "Number of egress IPs:\t\t\t%s" % len(egressIPCounter)
        print "--- with fluctuating distance\t\t%s (%.2f %%)" % (
            egressIPsWithFluctuatingDistanceNum,
            float(egressIPsWithFluctuatingDistanceNum) * 100 / len(egressIPCounter))
        print "--- with stable distance\t\t%s (%.2f %%)" % (
            egressIPsWithStableDistanceNum, float(egressIPsWithStableDistanceNum) * 100 / len(egressIPCounter))
        print "Number of egress ASes:\t\t\t%s" % len(egressASCounter)
        print "Number of neighbour IPs:\t\t%s" % len(neighbourIPCounter)
        print "Number of neighbour ASes:\t\t%s" % len(neighbourASCounter)

        print "\n::EGRESS IPs::"
        for ip in sorted(egressIPCounter, key=lambda x: egressIPCounter[x], reverse=True):
            print "%s\t%s" % (ip, egressIPCounter[ip])

        print "\n::EGRESS ASes::"
        for ip in sorted(egressASCounter, key=lambda x: egressASCounter[x], reverse=True):
            print "%s\t%s" % (ip, egressASCounter[ip])

        print "\n::Distance distribution (per egress point -- only those with fluctuacting distance)::\n"
        for ip in distanceInfo:
            if ip not in egressIPsWithFluctuatingDistance:  # skip egress points with stable distance
                continue
            distances = distanceInfo[ip].keys()
            occurrences = distanceInfo[ip].values()
            print "%s\t%s\t%s" % (ip, distances, occurrences)
            # print "%s\t%s\t%s" % (ip, distances, map(lambda x: float(x)/sum(occurrences), occurrences))
            print "%s\t%s\t%s" % (
                ip, distances, ["{0:0.2f}".format(i) for i in map(lambda x: float(x) / sum(occurrences), occurrences)])
            print ""

        print "\n::Distance+neighbourAS distribution (per egress point -- only those with fluctuacting distance)"
        for ip in distanceNeighbourASInfo:
            if ip not in egressIPsWithFluctuatingDistance:  # skip egress points with stable distance
                continue
            distancesNeighbourASes = distanceNeighbourASInfo[ip].keys()
            occurrences = distanceNeighbourASInfo[ip].values()
            print "%s\t%s\t%s" % (ip, distancesNeighbourASes, occurrences)
            # print "%s\t%s\t%s" % (ip, distancesNeighbourASes, map(lambda x: float(x)/sum(occurrences), occurrences))
            print "%s\t%s\t%s" % (ip, distancesNeighbourASes, ["{0:0.2f}".format(i) for i in
                                                               map(lambda x: float(x) / sum(occurrences), occurrences)])
            print ""

        print "\n::Distance+mplsHops distribution (per egress point -- only those with fluctuacting distance)"
        for ip in distanceNeighbourASInfo:
            if ip not in egressIPsWithFluctuatingDistance:  # skip egress points with stable distance
                continue
            distancesMpls = distanceMplsInfo[ip].keys()
            occurrences = distanceMplsInfo[ip].values()
            print "%s\t%s\t%s" % (ip, distancesMpls, occurrences)
            print "%s\t%s\t%s" % (
                ip, distancesMpls,
                ["{0:0.2f}".format(i) for i in map(lambda x: float(x) / sum(occurrences), occurrences)])
            print ""

    def compare(self, mapper, referenceCampaign):

        egressIPList = []
        noisyFirstEgressCount = 0
        distanceInfo = {}

        for t in self.traces:  # for all the traces in this campaign
            if t.ASHops == {}:
                t.IP2ASMappingAndRelated(
                    mapper)  # do IP2AS mapping on the whole trace - populates t.ASHops that is needed for tracing egress hops
            if t.hops == {}:
                continue
            if t.noisyFirstEgress == True:
                noisyFirstEgressCount += 1
                continue

            egressHop = t.getFirstEgressHop()
            if egressHop != None:

                egressIP = t.hops[egressHop][0]
                distance = egressHop + 1
                egressIPList.append(egressIP)

                # distanceInfo
                if egressIP in distanceInfo:
                    distanceInfo[egressIP].update([distance])
                else:
                    distanceInfo[egressIP] = Counter([distance])

        directDistance = {}
        for t in referenceCampaign.traces:
            directDistance[t.destination] = t.destDistance

        print "\n\n::TRANSIT vs DIRECT::\n"
        for ip in distanceInfo:
            distances = distanceInfo[ip].keys()
            occurrences = distanceInfo[ip].values()
            print "Transit: %s\t%s\t%s" % (ip, distances, occurrences)
            # print "Transit: %s\t%s\t%s" % (ip, distances, ["{0:0.2f}".format(i) for i in map(lambda x: float(x)/sum(occurrences), occurrences)])
            print "Direct: %s\t%s" % (ip, directDistance[ip])
            print ""


    def getDIRs(self, vp_data = None, outFileName = None):
        qFakeEgress = 0
        qNoReply = 0
        qDestDuplicated = 0
        qNoisyIngress = 0
        qLoops = 0
        qNoIngress = 0
        qDIRs_ok = 0
        if not vp_data:
            vp_data = defaultdict(dict)

        to_eliminate = []
        for AS in vp_data:
            for (i, e) in vp_data[AS]:
                if e not in self.tracesByDestination:
                    to_eliminate.append((AS, i, e))
        for (AS, i, e) in to_eliminate:
            del vp_data[AS][(i, e)]
            if not vp_data[AS]:
                del vp_data[AS]

        # couples = {(i, e) for AS in vp_data  \
        #             for (i, e) in vp_data[AS] \
        #             if e in self.tracesByDestination}

        couples = {(i, e) for AS in vp_data for (i, e) in vp_data[AS]}
        egresses = {e for (i, e) in couples}
        ingresses = {i for (i, e) in couples}

        print("#i =", len(ingresses), "# e =", len(egresses), "# i_e = ", len(couples))
        for t in self.traces:
            if t.destination not in egresses:
                qFakeEgress += 1
                continue
            if t.destReplied != 'R':
                qNoReply += 1
                continue
            if t.destination in t.hops.values():
                qDestDuplicated += 1
                continue
            found = 0
            for i_p in t.ingressPoints:
                if i_p.AS != t.destinationAS:
                    continue
                found = 1
                if i_p.isNoisy:
                    qNoisyIngress += 1
                    break
                DIR = list(t.getSubTrace(i_p.ipAddress, t.hops[len(t.hops)-1][0]))
                for _ in range(len(t.hops) + 1, t.destDistance):
                    DIR.append('q')
                DIR.append(t.destination)
                if loop_in_path(DIR):
                    qLoops += 1
                    break
                qDIRs_ok += 1
                if (i_p.ipAddress, t.destination) not in vp_data[i_p.AS]:
                    vp_data[i_p.AS][(i_p.ipAddress, t.destination)] = defaultdict(list)
                vp_data[i_p.AS][(i_p.ipAddress, t.destination)][DIR_LABEL].append(DIR)
                break
            if not found:
                qNoIngress += 1

        # for t in self.traces:
        #     if t.destReplied == 'R' and t.destination not in t.hops.values():
        #         for i_p in t.ingressPoints:
        #             if i_p.AS == t.destinationAS and not i_p.isNoisy:
        #                 DIR = list(t.getSubTrace(i_p.ipAddress, t.hops[len(t.hops)-1][0]))
        #                 for _ in range(len(t.hops) + 1, t.destDistance):
        #                     DIR.append('q')
        #                 DIR.append(t.destination)
        #                 if not loop_in_path(DIR):
        #                     qDIRs_ok += 1
        #                     if (i_p.ipAddress, t.destination) not in vp_data[i_p.AS]:
        #                         vp_data[i_p.AS][(i_p.ipAddress, t.destination)] = defaultdict(list)
        #                     vp_data[i_p.AS][(i_p.ipAddress, t.destination)][DIR_LABEL].append(DIR)

        f = open(outFileName, 'w')
        f.write("{i};{e};{i_e};{fake_e};{noreply};{dup};{noisy_i};{loops};{no_i};{ok};{q_t};".format(
                    i = len(ingresses),
                    e = len(egresses),
                    i_e = len(couples),
                    fake_e = qFakeEgress,
                    noreply = qNoReply,
                    dup = qDestDuplicated,
                    noisy_i = qNoisyIngress,
                    loops = qLoops,
                    no_i = qNoIngress,
                    ok = qDIRs_ok,
                    q_t = len(self.traces)))
        f.close()  
        return vp_data


    def getTIRs(self, vp_data = None):
        """
        Generates <NICKNAME>-egress.ips and  <NICKNAME>-firstegress.ips
        The list containst the list of the Provider AS egress points.
        """
        if not vp_data:
            vp_data = defaultdict(dict)


        for t in self.traces:
            for e_p in t.egressPoints:
                if not e_p.isNoisy:
                    for i_p in t.ingressPoints:
                        if e_p.ipAddress != i_p.ipAddress and not i_p.isNoisy:
                            if i_p.AS == e_p.AS and i_p.AS != t.sourceAS and i_p.AS != t.destinationAS and i_p.AS != t.ASHops[len(t.ASHops) - 1]:
                                TIR = t.getSubTrace(i_p.ipAddress, e_p.ipAddress)
                                # if not loop_in_path(TIR):
                                if (i_p.ipAddress, e_p.ipAddress) not in vp_data[i_p.AS]:
                                    vp_data[i_p.AS][(i_p.ipAddress, e_p.ipAddress)] = defaultdict(list)
                                vp_data[i_p.AS][(i_p.ipAddress, e_p.ipAddress)][TIR_LABEL].append((t.destination, TIR))
                                break

        # q_couples = 0
        # for AS in vp_data:
        #     q_couples += len(vp_data[AS].keys())
        # print("q_couples", q_couples)

        return vp_data



class EgressPoint:

    def __init__(self, ipAddress, AS, nextIpAddress, nextAS, hopNum):
        self.ipAddress = ipAddress
        self.AS = AS
        self.nextIpAddress = nextIpAddress
        self.nextAS = nextAS
        self.hopNum = hopNum
        self.isNoisy = nextAS in ['q', None, 'Private']

    def __repr__(self):
        return "%s|%s|%s|%s" % (self.ipAddress, self.AS, self.hopNum, self.isNoisy)


class IngressPoint:

    def __init__(self, ipAddress, AS, prevIpAddress, prevAS, hopNum):
        self.ipAddress = ipAddress
        self.AS = AS
        self.prevIpAddress = prevIpAddress
        self.prevAS = prevAS
        self.hopNum = hopNum
        self.isNoisy = prevAS in ['q', None, 'Private']

    def __repr__(self):
        return "%s|%s|%s|%s" % (self.ipAddress, self.AS, self.hopNum, self.isNoisy)


class MultipleEgressesException(Exception):
    pass


class MultipleASesException(Exception):
    pass


class AllNoisyException(Exception):
    pass


class AllShortException(Exception):
    pass


class AllDifferentIngressException(Exception):
    pass


class AllDifferentASPathException(Exception):
    pass


class IpNotOnPathException(Exception):
    pass


class UnderSampledException(Exception):
    pass


class AllPathsWithStarsException(Exception):
    pass

class DirectTraceRemovedWhileSkippingException(Exception):
    pass



class CWEgressPoint:
    """
    Campaign-wise Egress Point.
    Gathers a set of ASOnPath, all related to the same egress point.
    Transit traces related to different ingress points can be filtered.
    Provides statistics.

    """

    STABLE_LABEL = "STBL"
    VARIABLE_LABEL = "VRBL"

    def __init__(self, listOfASonPath, directTrace=None, directMDATrace=None, excludeNoisy=True, skipFirstHop=False):
        """

        :param listOfASonPath:
        :param directTrace:
        :param directMDATrace:
        :param excludeNoisy:
        :param skipFirstHop: if True, the first hop of both DIR (derived from directTrace) and TIRs (listOfASonPath)
                             is skipped
        """

        self.EgressPoints = listOfASonPath
        self.directTrace = directTrace
        self.directMDATrace = directMDATrace
        self.excludeNoisy = excludeNoisy

        self.hasDirectTrace = True if directTrace else False
        self.hasDirectMDATrace = True if directMDATrace else False

        if len(set([x.egressPoint.ipAddress for x in listOfASonPath])) > 1:
            raise MultipleEgressesException(
                "Egress Points with multiple IP addresses cannot be treated as a single campaign-wise egress point.\n"
                "Check your filter.")

        self.ipAddress = list(set([x.egressPoint.ipAddress for x in listOfASonPath]))[0]

        if len(set([x.egressPoint.AS for x in listOfASonPath])) > 1:
            raise MultipleASesException(
                "Egress Points with the same IP address should be mapped to the same AS. What's happened?")

        self.AS = list(set([x.egressPoint.AS for x in listOfASonPath]))[0]

        self.originatingTraces = [x.originatingTrace for x in listOfASonPath]

        #print len(self.EgressPoints)

        if skipFirstHop:
            for x in self.EgressPoints:
                #print
                #pprint(x.__dict__)  # old
                try:
                    x.skip1sthop()
                except CannotSkipHops, e:
                    # in case of CannotskipHops, delete x
                    print e
                    self.EgressPoints.remove(x)
                    #print len(self.EgressPoints)
                    #raw_input("tir removed")




                #pprint(x.__dict__)  # new
                #raw_input()

        if excludeNoisy:
            # listOfASonPath = [x for x in listOfASonPath if x.egressPoint.isNoisy==False]
            listOfASonPath = [x for x in self.EgressPoints if
                              (x.egressPoint.isNoisy == False and x.ingressPoint.isNoisy == False)]
            self.EgressPoints = listOfASonPath
        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllNoisyException("No non-noisy occurrence left for this CW Egress Point %s" % self.ipAddress)
            # return
        else:
            self.allNoisy = False

        # DISTANCE
        self.t_distanceL = [x.egressPoint.hopNum + 1 for x in self.EgressPoints]
        self.t_distanceC = Counter(self.t_distanceL)

        # MPLS HOPS
        self.t_mplsHopsL = [x.mplsHops for x in self.EgressPoints]
        self.t_mplsHopsC = Counter(self.t_mplsHopsL)

        # MPLS TUNNEL COUNT
        self.t_mplsTunnelCountL = [x.mplsTunnelCount for x in self.EgressPoints]
        self.t_mplsTunnelCountC = Counter(self.t_mplsTunnelCountL)

        # MPLS TUNNEL LENGTHS
        # self.t_mplsTunnelLengthsL = [x.mplsTunnelLengths for x in listOfASonPath]
        # self.t_mplsTunnelLengthsC = Counter(self.t_mplsTunnelLengthsL)

        # AS LENGTH
        self.t_ASLengthL = [x.ASLength for x in self.EgressPoints]
        self.t_ASLengthC = Counter(self.t_ASLengthL)

        # INGRESS POINTS
        self.t_ingressPointsL = [x.ingressPoint.ipAddress for x in self.EgressPoints]
        self.t_ingressPointsC = Counter(self.t_ingressPointsL)

        self.occ = len(self.EgressPoints)

        self.t_distanceStability = CWEgressPoint.STABLE_LABEL if len(
            self.t_distanceC.keys()) == 1 else CWEgressPoint.VARIABLE_LABEL
        self.t_distanceK = self.t_distanceC.keys()
        self.t_distanceOcc = self.t_distanceC.values()

        self.t_percMaxDistance = float(
            self.t_distanceOcc[self.t_distanceK.index(max(self.t_distanceK))]) * 100 / self.occ

        self.t_mplsHopsStability = CWEgressPoint.STABLE_LABEL if len(
            self.t_mplsHopsC.keys()) == 1 else CWEgressPoint.VARIABLE_LABEL
        self.t_mplsHopsK = self.t_mplsHopsC.keys()
        self.t_mplsHopsOcc = self.t_mplsHopsC.values()

        self.t_percMaxMplsHops = float(
            self.t_mplsHopsOcc[self.t_mplsHopsK.index(max(self.t_mplsHopsK))]) * 100 / self.occ

        self.t_mplsTunnelCountK = self.t_mplsTunnelCountC.keys()
        self.t_mplsTunnelCountOcc = self.t_mplsTunnelCountC.values()

        self.t_ASLengthStability = CWEgressPoint.STABLE_LABEL if len(
            self.t_ASLengthC.keys()) == 1 else CWEgressPoint.VARIABLE_LABEL
        self.t_ASLengthK = self.t_ASLengthC.keys()
        self.t_ASLengthOcc = self.t_ASLengthC.values()

        self.t_percMaxASLength = float(
            self.t_ASLengthOcc[self.t_ASLengthK.index(max(self.t_ASLengthK))]) * 100 / self.occ

        self.t_ingressPointsNum = len(self.t_ingressPointsC)
        self.t_ingressPointsK = self.t_ingressPointsC.keys()  # ingress IPs
        self.t_ingressPointsOcc = self.t_ingressPointsC.values()

        self.t_ASSeqs = set(
            [tuple(x.originatingTrace.ASSequence[:x.originatingTrace.ASSequence.index(self.AS) + 1]) for x in
             self.EgressPoints])

        if directTrace and self.AS in directTrace.ASInfo:

            # TODO: add variable telling if direct path is complete/egress point replied

            if skipFirstHop:

                #pprint (directTrace.ASInfo[self.AS].__dict__)  # old
                try:
                    directTrace.ASInfo[self.AS].skip1sthop()
                except CannotSkipHops, e:
                    print e
                    self.directTrace = None
                    self.hasDirectTrace = False
                    raise DirectTraceRemovedWhileSkippingException("unable to skip 1st hop DIR removed")
                    #raw_input("dir removed")

                #pprint (directTrace.ASInfo[self.AS].__dict__)  # new



                #pprint (directTrace.ASInfo[self.AS].__dict__)  # old
                # print directTrace.ASInfo[self.AS].ingressPoint

                #print "IN:", directTrace.ASInfo[self.AS].ingressPoint
                #print "hopnum:", directTrace.ASInfo[self.AS].ingressPoint.hopNum

                #raw_input()

                #newIngress = IngressPoint(directTrace.ASInfo[self.AS].originatingTrace.hops[directTrace.ASInfo[self.AS].ingressPoint.hopNum + 1][0],
                #                          directTrace.ASInfo[self.AS].ingressPoint.AS,
                #                          directTrace.ASInfo[self.AS].ingressPoint.ipAddress,
                #                          directTrace.ASInfo[self.AS].ingressPoint.prevAS,
                #                          directTrace.ASInfo[self.AS].ingressPoint.hopNum + 1)


                #if directTrace.ASInfo[self.AS].ASLength > 1:
                #    newDIR = ASOnPath(newIngress, directTrace.ASInfo[self.AS].egressPoint, directTrace.ASInfo[self.AS].originatingTrace, directTrace.ASInfo[self.AS].AS)
                #    directTrace.ASInfo[self.AS] = newDIR
                #else:
                #    directTrace = None
                # pprint(directTrace.ASInfo[self.AS].__dict__)  # new
                # print newIngress
                # raw_input()

                # BUG: if the above piece of code is run multiple times, weird things happen.
                # introduce some state variable in order to execute the "skip stuff" only one time

        if directTrace:


            self.d_distance = directTrace.destDistance

            self.d_ASSeq = tuple(directTrace.ASSequence)

            self.dt_distance = self.__compareDistance(self.d_distance, self.t_distanceK)
            self.dt_ASSeq = 'S' if (len(self.t_ASSeqs) == 1 and self.d_ASSeq == list(self.t_ASSeqs)[0]) else \
                'I' if self.d_ASSeq in self.t_ASSeqs else \
                    '?' if (self.d_distance == 0 and True in [x[:len(self.d_ASSeq)] == self.d_ASSeq for x in
                                                              self.t_ASSeqs]) else \
                        'D'

            self.d_ASLength = directTrace.ASInfo[self.AS].ASLength if self.AS in directTrace.ASInfo else '?'
            self.d_mplsHops = directTrace.ASInfo[self.AS].mplsHops if self.AS in directTrace.ASInfo else '?'

            # MPLS TUNNEL COUNT
            self.d_mplsTunnelCount = directTrace.ASInfo[
                self.AS].mplsTunnelCount if self.AS in directTrace.ASInfo else '?'
            self.dt_mplsTunnelCount = self.__compare2(self.d_mplsTunnelCount, self.t_mplsTunnelCountK)

            # MPLS TUNNEL LENGTHS
            # self.d_mplsTunnelLengths = directTrace.ASInfo[self.AS].mplsTunnelLengths if self.AS in directTrace.ASInfo else '?'

            self.d_ingressPoint = directTrace.ASInfo[
                self.AS].ingressPoint.ipAddress if self.AS in directTrace.ASInfo else '?'


            self.dt_ingressPoint = '?' if self.d_ingressPoint == '?' else \
                'S' if (len(self.t_ingressPointsK) == 1 and self.t_ingressPointsK[0] == self.d_ingressPoint) else \
                    'I' if self.d_ingressPoint in self.t_ingressPointsK else \
                        'D'

            self.dt_mplsHops = self.__compare2(self.d_mplsHops,
                                               self.t_mplsHopsK) if self.AS in directTrace.ASInfo else '?'
            self.dt_ASLength = self.__compare2(self.d_ASLength,
                                               self.t_ASLengthK) if self.AS in directTrace.ASInfo else '?'

            # T_dist < D_dist
            self.FIBInconsistencyMetric = float(sum([self.t_distanceC[k] for k in self.t_distanceC if
                                                     (k > self.d_distance and self.d_distance > 0)])) / self.occ
            self.FIBInconsistencyMetricABS = sum(
                [self.t_distanceC[k] for k in self.t_distanceC if (k > self.d_distance and self.d_distance > 0)])

            # T_dist != D_dist OR T_mplsHops != D_mplsHops
            diff_distIPs = [x.egressPoint for x in self.EgressPoints if
                            (x.egressPoint.hopNum + 1 != self.d_distance and self.d_distance > 0)]
            diff_mplsHopsIPs = [x.egressPoint for x in self.EgressPoints if
                                (x.mplsHops != self.d_mplsHops and self.d_mplsHops != '?')]

            self.FIBInconsistencyMetric2 = float(len(set(diff_distIPs).union(set(diff_mplsHopsIPs)))) / self.occ
            self.FIBInconsistencyMetric2ABS = len(set(diff_distIPs).union(set(diff_mplsHopsIPs)))

            # T_mplsTunnelCount != D_mplsTunnelCount
            # 1 vs 0 and 0 vs 1 cases are not considered
            # The only two good cases considered are:
            #     2 for transit vs 1 for direct (in case of Cisco egress - default all in LDP).
            #     2 for transit vs 0 for direct (in case of Juniper egress - default only BGP next hop self in LDP).

            # self.FIBInconsistencyMetric3 = float(sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (k != self.d_mplsTunnelCount and self.d_mplsTunnelCount != "?" and not(k==0 and self.d_mplsTunnelCount==1 or k==1 and self.d_mplsTunnelCount==0) ) ])) / self.occ
            # self.FIBInconsistencyMetric3ABS = sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (k != self.d_mplsTunnelCount and self.d_mplsTunnelCount != "?" and not(k==0 and self.d_mplsTunnelCount==1 or k==1 and self.d_mplsTunnelCount==0) )])

            self.FIBInconsistencyMetric3 = float(sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (
                    k == 2 and self.d_mplsTunnelCount == 1 or k == 2 and self.d_mplsTunnelCount == 0)])) / self.occ
            self.FIBInconsistencyMetric3ABS = sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (
                    k == 2 and self.d_mplsTunnelCount == 1 or k == 2 and self.d_mplsTunnelCount == 0)])

            # T_mplsTunnelCount != D_mplsTunnelCount OR T_dist != D_dist

            # diff_distIPs = [x.egressPoint for x in listOfASonPath if (x.egressPoint.hopNum+1!=self.d_distance and self.d_distance>0)]
            diff_mplsTunnelCountIPs = [x.egressPoint for x in self.EgressPoints if (
                    x.mplsTunnelCount == 2 and self.d_mplsTunnelCount == 1 or x.mplsTunnelCount == 2 and self.d_mplsTunnelCount == 0)]

            self.FIBInconsistencyMetric4 = float(len(set(diff_distIPs).union(set(diff_mplsTunnelCountIPs)))) / self.occ
            self.FIBInconsistencyMetric4ABS = len(set(diff_distIPs).union(set(diff_mplsTunnelCountIPs)))

        self.transitSubPathsSet = None
        self.transitSubPathsC = None
        self.transitSubPathsOcc = None
        self.transitSubPathsCard = None

        try:
            self.findTransitSubPaths(removePathsWithStars=False)
        except AllPathsWithStarsException, e:
            print e

        self.MDAdirectSubPathsSet = None  # set by self.findMDAdirectSubPaths
        self.MDAdirectSubPathsC = None  # set by self.findMDAdirectSubPaths
        self.MDAdirectSubPathsOcc = None  # set by self.findMDAdirectSubPaths
        self.MDAdirectSubPathsCard = None  # set by self.findMDAdirectSubPaths
        self.hasMDAdirectSubPath = False  # set by self.findMDAdirectSubPaths
        self.mdadt_overlap = None  # set by self.evaluateOverlap()
        self.strictlyOverlappingPathsNum = None  # set by self.evaluateOverlap()
        self.looselyOverlappingPathsNum = None  # set by self.evaluateOverlap()
        if directMDATrace:
            try:
                self.findMDAdirectSubPaths(removePathsWithStars=False)
                self.evaluateOverlap()
            except IpNotOnPathException, e:
                print e
            except AllPathsWithStarsException, e:
                print e


    def __HTunnel_check(self, tir, diR):
        """
        Check for the presence of hidden tunnels in the diR causing additional hops to appear.
        Returns True if the observed discrepancy in route length is possibly due to hidden mpls tunnels.
        False, otherwise.
        param tir: tuple, sequence of IP addresses
        param dir: tuple, sequence of IP addresses
        """
        intir = [x in tir for x in diR]     # list, elem is True if the IP is in tir, False otherwise
                                            # e.g. [True, True, False, False, False, True]

        indiR = [x in diR for x in tir]     # for a corner case
        testy = False in indiR  # True if one or more IPs in the TIR are not in the DIR, False otherwise
                                # (IP in the tir but not in the dir - A hidden MPLS tunnel cannot explain that!)
        groups = groupby(intir)
        tunnels = [(sum(1 for _ in group)) for label, group in groups if label==False]
        # tunnels: sequence of IP addresses not in TIR

        min_tunnel_len = 1 
        tunnel_count = len([x for x in tunnels if x >= min_tunnel_len])

        # print "IPs in TIR %s" % str(intir)
        # print tunnels
        # print tunnel_count
        # print "IPs in DIR %s" % str(indiR)
        # print testy

        # 1) return True only if 1 tunnel is found
        # 2) IPs composing the tunnel should be placed in the middle of the route
        # 3) if any IP in the TIR is not in the DIR return False!
        if tunnel_count == 1 and \
        testy == False and \
        intir[0] == True and intir[-1] == True:  # to check that new IPs are only in the middle of the route
            return True
        else:
            return False



    def getASOnPathInfo(self):
        """
        For each (sub)trace (from ingress to egress) associates metrics of interest
        and the outcomes related to their comparison.
        T: number of MPLS tunnels.
        H: number of IP hops (ASLen)
        d: direct trace --- related metrics are the same for traces in the CWEgressPoint, as they refer to the same direct trace.
        t: transit trace
        """

        ASOnPathInfo = defaultdict(dict)

        for x in self.EgressPoints:  # self.EgressPoints is listOfASonPath

            ASisNoisy = x.egressPoint.isNoisy or x.ingressPoint.isNoisy
            y = self.directTrace.ASInfo[self.AS]

            AS = AS_t = x.AS
            IN_t = x.ingressPoint.ipAddress
            OUT_t = x.egressPoint.ipAddress
            DST = x.originatingTrace.destination

            AS_d = y.AS
            IN_d = y.ingressPoint.ipAddress
            OUT_d = y.egressPoint.ipAddress

            T_d = y.mplsTunnelCount
            H_d = y.ASLength

            T_t = x.mplsTunnelCount
            H_t = x.ASLength

            OUTrtt_d = self.directTrace.destRTT
            OUTrtt_t = np.average(x.originatingTrace.rttsByIP[OUT_t]) if x.originatingTrace.rttsByIP.has_key(
                OUT_t) else 0

            destReplied = y.originatingTrace.destReplied == "R"

            # N: NOT REPLYING - egress point did not replied
            # U: UNCONCLUSIVE - subpaths containts "*"
            # E: EMPTY - 0vs0
            # I: winning cases, i.e., 2vs1 or 2vs0
            # C: (n,n) for n > 0
            # O: other

            E_set = [(0, 0)]
            I_set = [(2, 0), (2, 1)]
            C_set = [(n, n) for n in range(1, 21)]

            # IGP raises alarms only if MPLS_filter.
            # Accordingly, cases where paths dont match are divided
            # between cases with no MPLS or MPLS inconsistency (D) and cases with consistent MPLS (M)
            # M cases are assumed to be due to TE,
            # while D cases are "unwanted deflections"
            MPLS_filter = (T_t, T_d) in E_set or (T_t, T_d) in I_set
            #subpathsMatch = "N" if not destReplied else "S" if x.subpath == y.subpath else "D" if MPLS_filter else "M"



            # 1=True, 0=False
            HTunnel = int(self.__HTunnel_check(x.subpath, y.subpath))
            duplicates_in_dir = int(set([y.subpath.count(z) for z in y.subpath if z!="q"]) != set([1]))
            duplicates_in_tir = int(set([x.subpath.count(z) for z in x.subpath if z!="q"]) != set([1]))


            # subpathsMatch variable encodes more than if paths match.
            # this info is dumped in MDAInput files and used by ECMP exploration made by perdest-MDA.
            subpathsMatch = "N" if not destReplied else \
                            "S" if x.subpath == y.subpath else \
                            "H" if (duplicates_in_dir==1 or duplicates_in_tir==1 or HTunnel==1) else \
                            "D" if MPLS_filter else \
                            "M"

            sub_t = ",".join(x.subpath)
            sub_d = ",".join(y.subpath)

            

            if destReplied:

                M_H = ">" if H_d > H_t else "<" if H_d < H_t else "="

                M_T = "U" if x.containsStars else \
                    "E" if (T_t, T_d) in E_set else \
                        "I" if (T_t, T_d) in I_set else \
                            "C" if (T_t, T_d) in C_set else \
                                "O"
            else:
                M_T = "N"
                M_H = "N"

            if OUTrtt_t != 0 and OUTrtt_d != 0:
                M_RTT = OUTrtt_t - OUTrtt_d
            else:
                M_RTT = "N"

            if IN_t != IN_d or AS_t != AS_d or OUT_t != y.originatingTrace.destination:
                print "SOMETHING WRONG!!!"
                print IN_t
                print IN_d
                print AS_t
                print AS_d
                print OUT_t
                print y.originatingTrace.destination
                raw_input()

            ASOnPathInfo[(AS, OUT_t, IN_t, DST)] = {"AS": AS,
                                                    "OUT": OUT_t,
                                                    "IN": IN_t,
                                                    "DST": DST,
                                                    "M_H": M_H,
                                                    "M_T": M_T,
                                                    "H_t": H_t,
                                                    "H_d": H_d,
                                                    "T_t": T_t,
                                                    "T_d": T_d,
                                                    "OUTrtt_t": OUTrtt_t,
                                                    "OUTrtt_d": OUTrtt_d,
                                                    "M_RTT": M_RTT,
                                                    "subpathsMatch": subpathsMatch,
                                                    "sub_t": sub_t,
                                                    "sub_d": sub_d,
                                                    "isnoisy": ASisNoisy,
                                                    "dups_in_dir": duplicates_in_dir,
                                                    "dups_in_tir": duplicates_in_tir,
                                                    "HTunnel": HTunnel,
                                                    "VP": x.originatingTrace.originatingCampaign.nickname
                                                    }

        return ASOnPathInfo

    #                print x.originatingTrace
    #                print
    #                print y.originatingTrace
    #
    #                print AS_t == AS_d
    #                print IN_t == IN_d
    #                print OUT_t == OUT_d
    #
    #                print "", OUT_t
    #                print "", OUT_d
    #
    #                print "T_d", T_d
    #                print "T_t", T_t
    #
    #                print "H_d", H_d
    #                print "H_t", H_t
    #
    #                if H_t != H_d:
    #                    raw_input()

    def __compareDistance(self, dd, tds):
        """
        compare direct distance towards an egress point against (the maximum) if transit distances.
        returns "?" if direct distance is not available.
        """
        ret = "?" if dd == 0 else "<" if dd < max(tds) else "=" if dd == max(tds) else ">"
        return ret

    def __compare2(self, dd, tds):
        """
        Same as compareDistance, but does not consider dd=0 as a special value.
        It is used for comparintg other metrics (e.g., ASHops, MPLS hops)
        """
        ret = "<" if dd < max(tds) else "=" if dd == max(tds) else ">"
        return ret

    def __removePathsWithStars(self, pathList):
        newPathList = []
        for t in pathList:
            if not "q" in t:
                newPathList.append(t)
        return newPathList

    def findTransitSubPaths(self, removePathsWithStars=False):
        """
        Finds the set of Direct paths from ingress(es) to the egress to related transit subpaths.
        And sets related info.
        """

        mdaTrace = self.directMDATrace

        egressIP = self.ipAddress
        transitSubPaths = []
        ingressIPs = []
        for x in self.EgressPoints:
            ingressIP = x.ingressPoint.ipAddress  # ASOnPaths could have different ingress point
            try:
                # print x.originatingTrace
                # print "EGR", egressIP
                # print "ING", ingressIP
                transitSubPath = x.originatingTrace.getSubTrace(ingressIP, egressIP)
                transitSubPaths.append(transitSubPath)
            except IpNotOnPathException, e:  # e.g., in case of non-replying egress
                print e
                raw_input()

        if removePathsWithStars:
            transitSubPaths = self.__removePathsWithStars(transitSubPaths)
        if len(transitSubPaths) == 0:
            raise AllPathsWithStarsException(
                "All transit subpaths from %s to %s contains at least a '*'" % (ingressIP, egressIP))
        self.transitSubPathsSet = set(transitSubPaths)
        self.transitSubPathsC = Counter(transitSubPaths)
        self.transitSubPathsOcc = self.transitSubPathsC.values()
        self.transitSubPathsCard = len(self.transitSubPathsSet)

    def findMDAdirectSubPaths(self, removePathsWithStars=False):
        """
        Finds the set of MDA paths from ingress(es) to the egress to related transit subpaths.
        And sets related info.
        """
        mdaTrace = self.directMDATrace
        egressIP = self.ipAddress
        mdaSubPaths = []
        for ingressIP in set(self.t_ingressPointsK):
            try:
                mdaSubPaths.extend(mdaTrace.getSimplePaths(ingressIP, egressIP))
            except IpNotOnPathException, e:
                raise IpNotOnPathException(e)
                # print mdaTrace.destination
                # print mdaTrace.G.edges()
                # raw_input()

        if removePathsWithStars:
            mdaSubPaths = self.__removePathsWithStars(mdaSubPaths)
        if len(mdaSubPaths) == 0:
            raise AllPathsWithStarsException(
                "All MDA direct subpaths from %s to %s contains at least a '*'" % (ingressIP, egressIP))
        self.hasMDAdirectSubPath = True
        self.MDAdirectSubPathsSet = set(map(tuple, mdaSubPaths))
        self.MDAdirectSubPathsC = Counter(mdaSubPaths)
        self.MDAdirectSubPathsOcc = self.MDAdirectSubPathsC.values()
        self.MDAdirectSubPathsCard = len(self.MDAdirectSubPathsSet)

    def evaluateOverlap(self):
        """
        Compares the set of MDA paths from ingress(es) to the egress to related transit subpaths.
        """
        TisSubset = self.transitSubPathsSet < self.MDAdirectSubPathsSet
        DisSubset = self.MDAdirectSubPathsSet < self.transitSubPathsSet
        Congruent = self.transitSubPathsSet == self.MDAdirectSubPathsSet
        Disjoint = self.transitSubPathsSet.isdisjoint(self.MDAdirectSubPathsSet)

        self.mdadt_overlap = "TisSubset" if TisSubset else \
            "DisSubset" if DisSubset else \
                "Congruent" if Congruent else \
                    "Disjoint" if Disjoint else \
                        "Intersected"

        strictlyOverlappingPaths = 0
        for p1 in self.MDAdirectSubPathsSet:
            if True in [evaluatePathMatch(p1, x, strict=True) for x in self.transitSubPathsSet]:
                strictlyOverlappingPaths += 1

        looselyOverlappingPaths = 0
        for p1 in self.MDAdirectSubPathsSet:
            if True in [evaluatePathMatch(p1, x, strict=False) for x in self.transitSubPathsSet]:
                looselyOverlappingPaths += 1

        self.strictlyOverlappingPathsNum = strictlyOverlappingPaths
        self.looselyOverlappingPathsNum = looselyOverlappingPaths

    def DTVector(self):
        # (D?TASPath, D?TIngressPoints, TDistanceStability, D?TDistance, TASHopsStability, D?TASHops, TMPLSHopsStability, D?TMPLSHops)
        return (
            self.dt_ASSeq, self.dt_ingressPoint, self.t_distanceStability, self.dt_distance, self.t_ASLengthStability,
            self.dt_ASLength, self.t_mplsHopsStability, self.dt_mplsHops)

    @staticmethod
    def translateCode(code):

        diz = {
            CWEgressPoint.BGPDETOUR: "BGPDETOUR",
            CWEgressPoint.DIFFERENTINGRESS: "DIFFERENTINGRESS",
            CWEgressPoint.ALLTHESAME: "ALLTHESAME",
            CWEgressPoint.ALLTHESAME_SHORTERMPLSTUNNEL: "ALLTHESAME_SHORTERMPLSTUNNEL",
            CWEgressPoint.INCFIB1_SHORTERMPLSTUNNEL: "INCFIB1_SHORTERMPLSTUNNEL",
            CWEgressPoint.INCFIB2_LONGERMPLSTUNNEL: "INCFIB2_LONGERMPLSTUNNEL",
            CWEgressPoint.INCFIB3_SAMELENGTHMPLSTUNNEL: "INCFIB3_SAMELENGTHMPLSTUNNEL",
            CWEgressPoint.MULTIPLEINGRESSES: "MULTIPLEINGRESSES*",
            CWEgressPoint.ECMP: "ECMP",
            CWEgressPoint.TRANSITCANBESHORTER: "TRANSITCANBESHORTER",
            CWEgressPoint.TRANSITALWAYSSHORTER: "TRANSITALWAYSSHORTER",
            CWEgressPoint.SPURIOUS1: "SPURIOUS1",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.SPURIOUS2: "SPURIOUS2",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.SPURIOUS3: "SPURIOUS3",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.SPURIOUS4: "SPURIOUS4",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.NOLLOSO: "UNKNOWN"
        }

        return diz[code]

    BGPDETOUR = 0
    DIFFERENTINGRESS = 1
    ALLTHESAME = 2
    ALLTHESAME_SHORTERMPLSTUNNEL = 3
    INCFIB1_SHORTERMPLSTUNNEL = 4
    INCFIB2_LONGERMPLSTUNNEL = 5
    MULTIPLEINGRESSES = 6
    INCFIB3_SAMELENGTHMPLSTUNNEL = 7
    ECMP = 8
    TRANSITALWAYSSHORTER = 9
    TRANSITCANBESHORTER = 10
    SPURIOUS1 = 11
    SPURIOUS2 = 12
    SPURIOUS3 = 13
    SPURIOUS4 = 14
    NOLLOSO = 999

    def classification(self):

        if self.dt_ASSeq == "D":
            return self.BGPDETOUR

        if self.dt_ingressPoint == "D":
            return self.DIFFERENTINGRESS

        if self.dt_ingressPoint == "I":
            return self.MULTIPLEINGRESSES

        #        if self.dt_ASSeq == "S"                                     and\
        #           self.dt_ingressPoint == "S"                              and\
        #           self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL and\
        #           self.t_percMaxDistance < 55 and\
        #           self.t_percMaxDistance > 45:
        #            return self.ECMP
        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == ">" and \
                self.dt_ASLength == "=":
            return self.SPURIOUS1

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "=":
            return self.SPURIOUS2

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "=" and \
                self.dt_ASLength == ">":
            return self.SPURIOUS3

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "<":
            return self.SPURIOUS4

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "=":
            return self.TRANSITCANBESHORTER

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == ">" and \
                self.dt_ASLength == ">":
            return self.TRANSITALWAYSSHORTER

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.t_distanceStability == CWEgressPoint.STABLE_LABEL and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "=" and \
                self.dt_mplsHops == "=":
            return self.ALLTHESAME

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.t_distanceStability == CWEgressPoint.STABLE_LABEL and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "=" and \
                self.dt_mplsHops == "<":
            return self.ALLTHESAME_SHORTERMPLSTUNNEL

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "<" and \
                self.dt_mplsHops == "<":
            return self.INCFIB1_SHORTERMPLSTUNNEL
        # self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL   and\

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "<" and \
                self.dt_mplsHops == ">":
            return self.INCFIB2_LONGERMPLSTUNNEL
        # self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL   and\

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "<" and \
                self.dt_mplsHops == "=":
            return self.INCFIB3_SAMELENGTHMPLSTUNNEL
        # self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL   and\

        else:
            return self.NOLLOSO

    @staticmethod
    def toLineHeader():
        return ";".join([
            "{AS}",
            "{ip}",
            "{fqdn}",
            "{occ}",
            "{incscore}",
            "{incscore2}",
            "{tdiststab}",
            "{tdist}",
            "{tdistocc}",
            "{percMaxDistance}",
            "{ddist}",
            "{tmplshopsstab}",
            "{tmplshops}",
            "{tmplshopsocc}",
            "{percMaxMplsHops}",
            "{dmplshops}",
            "{tashopsstab}",
            "{tashops}",
            "{tashopsocc}",
            "{percMaxASHops}",
            "{dashops}",
            "{t_ingress}",
            "{t_ingressocc}",
            "{d_ingress}",
            "{d_t_dist}",
            "{d_t_aspath}",
            "{d_t_ingress}",
            "{d_t_ashops}",
            "{d_t_mplshops}",
            "{classification}"]).format(
            AS="ASN",
            ip="IP",
            fqdn="FQDN",
            occ="Occurrences", \
 \
            d_t_dist="D?T Distance",
            d_t_aspath="D?T AS Path",
            d_t_ingress="D?T Ingress Points",
            d_t_ashops="D?T AS Hops",
            d_t_mplshops="D?T MPLS Hops", \
 \
            tdiststab="Transit Distance Stability",
            tdistocc="Transit Distance Occurrences",
            tdist="Transit Distance",
            ddist="Direct Distance", \
 \
            tmplshopsstab="Transit MPLS Hops Stability",
            tmplshopsocc="Transit MPLS Hops Occurrences",
            tmplshops="Transit MPLS Hops",
            dmplshops="Direct MPLS Hops", \
 \
            tashopsstab="Transit Hops in AS Stability",
            tashopsocc="Transit Hops in AS Occurrences",
            tashops="Transit Hops in AS",
            dashops="Direct Hops in AS", \
 \
            t_ingress="Transit Ingress Points",
            t_ingressocc="Transit Ingress Points Occurrences",
            d_ingress="Direct Ingress Point", \
 \
            classification="Classification",
            percMaxASHops="% max AS Hops",
            percMaxMplsHops="% max MPLS Hops",
            percMaxDistance="% max Distance",
            incscore="Fraction of Transit Paths longer than the Direct Path (LONGER DISTANCE)",
            incscore2="Fraction of Transit Paths with DIFFERENT DISTANCE OR DIFFERENT MPLSHOPS than the Direct Path"
        )

    #    @staticmethod
    #    def toLineHeader():
    #        return "{AS};{ip};{fqdn};{occ};\
    # {incscore};{incscore2};\
    # {tdiststab};{tdist};{tdistocc};{percMaxDistance};{ddist};\
    # {tmplshopsstab};{tmplshops};{tmplshopsocc};{percMaxMplsHops};{dmplshops};\
    # {tashopsstab};{tashops};{tashopsocc};{percMaxASHops};{dashops};\
    # {t_ingress};{t_ingressocc};{d_ingress};\
    # {d_t_dist};{d_t_aspath};{d_t_ingress};{d_t_ashops};{d_t_mplshops};\
    # {classification};".format(
    #                                            AS="ASN",
    #                                            ip="IP",
    #                                            fqdn="FQDN",
    #                                            occ="Occurrences",
    #                                            \
    #                                            d_t_dist="D?T Distance",
    #                                            d_t_aspath="D?T AS Path",
    #                                            d_t_ingress="D?T Ingress Points",
    #                                            d_t_ashops="D?T AS Hops",
    #                                            d_t_mplshops="D?T MPLS Hops",
    #                                            \
    #                                            tdiststab="Transit Distance Stability",
    #                                            tdistocc="Transit Distance Occurrences",
    #                                            tdist="Transit Distance",
    #                                            ddist="Direct Distance",
    #                                            \
    #                                            tmplshopsstab="Transit MPLS Hops Stability",
    #                                            tmplshopsocc="Transit MPLS Hops Occurrences",
    #                                            tmplshops="Transit MPLS Hops",
    #                                            dmplshops="Direct MPLS Hops",
    #                                            \
    #                                            tashopsstab="Transit Hops in AS Stability",
    #                                            tashopsocc="Transit Hops in AS Occurrences",
    #                                            tashops="Transit Hops in AS",
    #                                            dashops="Direct Hops in AS",
    #                                            \
    #                                            t_ingress="Transit Ingress Points",
    #                                            t_ingressocc="Transit Ingress Points Occurrences",
    #                                            d_ingress="Direct Ingress Point",
    #                                            \
    #                                            classification="Classification",
    #                                            percMaxASHops="% max AS Hops",
    #                                            percMaxMplsHops="% max MPLS Hops",
    #                                            percMaxDistance="% max Distance",
    #                                            incscore="Fraction of Transit Paths longer than the Direct Path (LONGER DISTANCE)",
    #                                            incscore2="Fraction of Transit Paths with DIFFERENT DISTANCE OR DIFFERENT MPLSHOPS than the Direct Path"
    #                                            )

    def toLine(self):
        return ";".join(["{AS}",
                         "{ip}",
                         "{fqdn}",
                         "{occ}",
                         "{incscore:.2f}",
                         "{incscore2:.2f}",
                         "{tdiststab}",
                         "{tdist}",
                         "{tdistocc}",
                         "{percMaxDistance:.2f}",
                         "{ddist}",
                         "{tmplshopsstab}",
                         "{tmplshops}",
                         "{tmplshopsocc}",
                         "{percMaxMplsHops:.2f}",
                         "{dmplshops}",
                         "{tashopsstab}",
                         "{tashops}",
                         "{tashopsocc}",
                         "{percMaxASHops:.2f}",
                         "{dashops}",
                         "{t_ingress}",
                         "{t_ingressocc}",
                         "{d_ingress}",
                         "{d_t_dist}",
                         "{d_t_aspath}",
                         "{d_t_ingress}",
                         "{d_t_ashops}",
                         "{d_t_mplshops}",
                         "{classification}"]).format(
            AS=self.AS,
            ip=self.ipAddress,
            fqdn=reverseDNS(self.ipAddress),
            occ=self.occ, \
 \
            d_t_dist=self.dt_distance,
            d_t_aspath=self.dt_ASSeq,
            d_t_ingress=self.dt_ingressPoint,
            d_t_ashops=self.dt_ASLength,
            d_t_mplshops=self.dt_mplsHops, \
 \
            tdiststab=self.t_distanceStability,
            tdistocc=self.t_distanceOcc,
            tdist=self.t_distanceK,
            ddist=self.d_distance, \
 \
            tmplshopsstab=self.t_mplsHopsStability,
            tmplshopsocc=self.t_mplsHopsOcc,
            tmplshops=self.t_mplsHopsK,
            dmplshops=self.d_mplsHops, \
 \
            tashopsstab=self.t_ASLengthStability,
            tashopsocc=self.t_ASLengthOcc,
            tashops=self.t_ASLengthK,
            dashops=self.d_ASLength, \
 \
            d_ingress=self.d_ingressPoint,
            t_ingress=self.t_ingressPointsK,
            t_ingressocc=self.t_ingressPointsOcc, \
 \
            classification=CWEgressPoint.translateCode(self.classification()),
            percMaxASHops=self.t_percMaxASLength,
            percMaxMplsHops=self.t_percMaxMplsHops,
            percMaxDistance=self.t_percMaxDistance,
            incscore=self.FIBInconsistencyMetric,
            incscore2=self.FIBInconsistencyMetric2
        )

    def toLine2(self):

        return ";".join([
            "{overlap}",
            "{strictlyoverlapping}",
            "{looselyoverlapping}",
            "{intersectionsize}",
            "{intersectionocc}",
            "{transitcount}",
            "{transitocc}",
            "{directmdacount}",
            "{directmdaocc}"]).format(overlap=self.mdadt_overlap if self.mdadt_overlap else "?",
                                      transitcount=self.transitSubPathsCard,
                                      transitocc=self.transitSubPathsOcc,
                                      directmdacount=self.MDAdirectSubPathsCard if self.hasDirectMDATrace else "?",
                                      directmdaocc=self.MDAdirectSubPathsOcc if self.hasDirectMDATrace else "?",
                                      intersectionsize=len(self.transitSubPathsSet.intersection(
                                          self.MDAdirectSubPathsSet)) if self.hasMDAdirectSubPath else "?",
                                      intersectionocc=[self.transitSubPathsC[x] for x in
                                                       self.transitSubPathsSet.intersection(
                                                           self.MDAdirectSubPathsSet)] if self.hasMDAdirectSubPath else "?",
                                      strictlyoverlapping=self.strictlyOverlappingPathsNum,
                                      looselyoverlapping=self.looselyOverlappingPathsNum)

    @staticmethod
    def toLine2Header():
        return ";".join(["{overlap}",
                         "{strictlyoverlapping}",
                         "{looselyoverlapping}",
                         "{intersectionsize}",
                         "{intersectionocc}",
                         "{transitcount}",
                         "{transitocc}",
                         "{directmdacount}",
                         "{directmdaocc}"]).format(overlap="Overlap outcome",
                                                   transitcount="Different transit subpaths",
                                                   transitocc="Transit subpaths occurrences",
                                                   directmdacount="MDA direct subpaths",
                                                   directmdaocc="MDA direct subpaths occurrences",
                                                   intersectionsize="Overlap size",
                                                   intersectionocc="Overlap occurrences",
                                                   strictlyoverlapping="Stricly Overlapping Paths",
                                                   looselyoverlapping="Loosely Overlapping Paths")

    def excludeDistanceOutliers(self, thresh=1):
        """
        Excludes egress points occurrences with distances whose occurrence is less than <thresh>% of the total (if any).
        These cases are due to route flapping.
        """

        perc = map(lambda x: float(x) * 100 / self.occ, self.t_distanceC.values())
        valsToRemove = [self.t_distanceC.keys()[i] for i in [perc.index(x) for x in perc if x <= thresh]]

        # if there are occurrences to be removed, call again the contructor
        if valsToRemove != []:
            listOfASonPath = [x for x in self.EgressPoints if
                              x.egressPoint.hopNum + 1 not in valsToRemove]  # remove egress points with distance in valsToRemove
            self = self.__init__(listOfASonPath, self.directTrace, self.directMDATrace,
                                 excludeNoisy=self.excludeNoisy)  # update data structures

    def excludeDifferentIngressPoints(self):
        """
        Excludes egress points when the ingress point is different than that of the Direct Trace.
        """
        listOfASonPath = [x for x in self.EgressPoints if x.ingressPoint.ipAddress == self.d_ingressPoint]

        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllDifferentIngressException(
                "No occurrence entering the AS through %s for this CW Egress Point: %s" % (
                    self.d_ingressPoint, self.ipAddress))
        else:
            self = self.__init__(listOfASonPath, self.directTrace, self.directMDATrace,
                                 excludeNoisy=self.excludeNoisy)  # update data structures

    def excludeDifferentASSeqs(self):
        """
        Exclude egress points whose path crossed different AS Sequences.
        """

        listOfASonPath = [x for x in self.EgressPoints if tuple(
            x.originatingTrace.ASSequence[:x.originatingTrace.ASSequence.index(self.AS) + 1]) == self.d_ASSeq]

        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllDifferentASPathException(
                "No occurrence crossing %s for this CW Egress Point: %s" % (self.d_ASSeq, self.ipAddress))
        else:
            self = self.__init__(listOfASonPath, self.directTrace, self.directMDATrace,
                                 excludeNoisy=self.excludeNoisy)  # update data structures

    def excludeUnderSampled(self, thresh):
        """
        Raises exception if self.occ < thresh.
        """

        if self.occ < thresh:
            # when all egress points are noisy, raise exception
            raise UnderSampledException("Only %s occurrences (less than %s) left for this CW Egress Point: %s" % (
                self.occ, thresh, self.ipAddress))

    def excludeShortASes(self, minLength=3):
        """
        Excludes egress points occurrences with ASLength shorter than minLenght (if any).
        These cases are potentially due to HIDDEN tunnels.
        """

        listOfASonPath = [x for x in self.EgressPoints if
                          x.ASLength >= minLength]  # remove egress points in ASes shorter than minLength

        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllShortException(
                "No occurrence longer than %s left for this CW Egress Point %s" % (minLength, self.ipAddress))
        else:
            self = self.__init__(listOfASonPath, self.directTrace, self.directMDATrace,
                                 excludeNoisy=self.excludeNoisy)  # update data structures


class CWEgressPoint2:
    """
    Campaign-wise Egress Point.
    Gathers a set of ASOnPath, all related to the same egress point.
    Transit traces related to different ingress points can be filtered.
    Provides statistics.

    Associates related direct trace (same ingress and egress).

    Associates list of

    """

    STABLE_LABEL = "STBL"
    VARIABLE_LABEL = "VRBL"

    def __init__(self, listOfASonPath, directTrace=None, dstMDA=None, excludeNoisy=True):

        self.EgressPoints = listOfASonPath
        self.directTrace = directTrace
        self.dstMDA = dstMDA
        self.excludeNoisy = excludeNoisy

        self.hasDirectTrace = True if directTrace else False
        self.hasDstMDA = True if dstMDA else False

        if len(set([x.egressPoint.ipAddress for x in listOfASonPath])) > 1:
            raise MultipleEgressesException(
                "Egress Points with multiple IP addresses cannot be treated as a single campaign-wise egress point.\n"
                "Check your filter.")

        self.ipAddress = list(set([x.egressPoint.ipAddress for x in listOfASonPath]))[0]

        if len(set([x.egressPoint.AS for x in listOfASonPath])) > 1:
            raise MultipleASesException(
                "Egress Points with the same IP address should be mapped to the same AS. What's happened?")

        self.AS = list(set([x.egressPoint.AS for x in listOfASonPath]))[0]

        self.originatingTraces = [x.originatingTrace for x in listOfASonPath]

        if excludeNoisy:
            # listOfASonPath = [x for x in listOfASonPath if x.egressPoint.isNoisy==False]
            listOfASonPath = [x for x in listOfASonPath if
                              (x.egressPoint.isNoisy == False and x.ingressPoint.isNoisy == False)]
            self.EgressPoints = listOfASonPath
        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllNoisyException("No non-noisy occurrence left for this CW Egress Point %s" % self.ipAddress)
            # return
        else:
            self.allNoisy = False

        # DISTANCE
        self.t_distanceL = [x.egressPoint.hopNum + 1 for x in listOfASonPath]
        self.t_distanceC = Counter(self.t_distanceL)

        # MPLS HOPS
        self.t_mplsHopsL = [x.mplsHops for x in listOfASonPath]
        self.t_mplsHopsC = Counter(self.t_mplsHopsL)

        # MPLS TUNNEL COUNT
        self.t_mplsTunnelCountL = [x.mplsTunnelCount for x in listOfASonPath]
        self.t_mplsTunnelCountC = Counter(self.t_mplsTunnelCountL)

        # MPLS TUNNEL LENGTHS
        # self.t_mplsTunnelLengthsL = [x.mplsTunnelLengths for x in listOfASonPath]
        # self.t_mplsTunnelLengthsC = Counter(self.t_mplsTunnelLengthsL)

        # AS LENGTH
        self.t_ASLengthL = [x.ASLength for x in listOfASonPath]
        self.t_ASLengthC = Counter(self.t_ASLengthL)

        # INGRESS POINTS
        self.t_ingressPointsL = [x.ingressPoint.ipAddress for x in listOfASonPath]
        self.t_ingressPointsC = Counter(self.t_ingressPointsL)

        self.occ = len(listOfASonPath)

        self.t_distanceStability = CWEgressPoint.STABLE_LABEL if len(
            self.t_distanceC.keys()) == 1 else CWEgressPoint.VARIABLE_LABEL
        self.t_distanceK = self.t_distanceC.keys()
        self.t_distanceOcc = self.t_distanceC.values()

        self.t_percMaxDistance = float(
            self.t_distanceOcc[self.t_distanceK.index(max(self.t_distanceK))]) * 100 / self.occ

        self.t_mplsHopsStability = CWEgressPoint.STABLE_LABEL if len(
            self.t_mplsHopsC.keys()) == 1 else CWEgressPoint.VARIABLE_LABEL
        self.t_mplsHopsK = self.t_mplsHopsC.keys()
        self.t_mplsHopsOcc = self.t_mplsHopsC.values()

        self.t_percMaxMplsHops = float(
            self.t_mplsHopsOcc[self.t_mplsHopsK.index(max(self.t_mplsHopsK))]) * 100 / self.occ

        self.t_mplsTunnelCountK = self.t_mplsTunnelCountC.keys()
        self.t_mplsTunnelCountOcc = self.t_mplsTunnelCountC.values()

        self.t_ASLengthStability = CWEgressPoint.STABLE_LABEL if len(
            self.t_ASLengthC.keys()) == 1 else CWEgressPoint.VARIABLE_LABEL
        self.t_ASLengthK = self.t_ASLengthC.keys()
        self.t_ASLengthOcc = self.t_ASLengthC.values()

        self.t_percMaxASLength = float(
            self.t_ASLengthOcc[self.t_ASLengthK.index(max(self.t_ASLengthK))]) * 100 / self.occ

        self.t_ingressPointsNum = len(self.t_ingressPointsC)
        self.t_ingressPointsK = self.t_ingressPointsC.keys()  # ingress IPs
        self.t_ingressPointsOcc = self.t_ingressPointsC.values()

        self.t_ASSeqs = set(
            [tuple(x.originatingTrace.ASSequence[:x.originatingTrace.ASSequence.index(self.AS) + 1]) for x in
             listOfASonPath])

        if directTrace:
            self.d_distance = directTrace.destDistance

            self.d_ASSeq = tuple(directTrace.ASSequence)

            self.dt_distance = self.__compareDistance(self.d_distance, self.t_distanceK)
            self.dt_ASSeq = 'S' if (len(self.t_ASSeqs) == 1 and self.d_ASSeq == list(self.t_ASSeqs)[0]) else \
                'I' if self.d_ASSeq in self.t_ASSeqs else \
                    '?' if (self.d_distance == 0 and True in [x[:len(self.d_ASSeq)] == self.d_ASSeq for x in
                                                              self.t_ASSeqs]) else \
                        'D'

            self.d_ASLength = directTrace.ASInfo[self.AS].ASLength if self.AS in directTrace.ASInfo else '?'
            self.d_mplsHops = directTrace.ASInfo[self.AS].mplsHops if self.AS in directTrace.ASInfo else '?'

            # MPLS TUNNEL COUNT
            self.d_mplsTunnelCount = directTrace.ASInfo[
                self.AS].mplsTunnelCount if self.AS in directTrace.ASInfo else '?'
            self.dt_mplsTunnelCount = self.__compare2(self.d_mplsTunnelCount, self.t_mplsTunnelCountK)

            # MPLS TUNNEL LENGTHS
            # self.d_mplsTunnelLengths = directTrace.ASInfo[self.AS].mplsTunnelLengths if self.AS in directTrace.ASInfo else '?'

            self.d_ingressPoint = directTrace.ASInfo[
                self.AS].ingressPoint.ipAddress if self.AS in directTrace.ASInfo else '?'

            self.dt_ingressPoint = '?' if self.d_ingressPoint == '?' else \
                'S' if (len(self.t_ingressPointsK) == 1 and self.t_ingressPointsK[0] == self.d_ingressPoint) else \
                    'I' if self.d_ingressPoint in self.t_ingressPointsK else \
                        'D'

            self.dt_mplsHops = self.__compare2(self.d_mplsHops,
                                               self.t_mplsHopsK) if self.AS in directTrace.ASInfo else '?'
            self.dt_ASLength = self.__compare2(self.d_ASLength,
                                               self.t_ASLengthK) if self.AS in directTrace.ASInfo else '?'

            # T_dist < D_dist
            self.FIBInconsistencyMetric = float(sum([self.t_distanceC[k] for k in self.t_distanceC if
                                                     (k > self.d_distance and self.d_distance > 0)])) / self.occ
            self.FIBInconsistencyMetricABS = sum(
                [self.t_distanceC[k] for k in self.t_distanceC if (k > self.d_distance and self.d_distance > 0)])

            # T_dist != D_dist OR T_mplsHops != D_mplsHops
            diff_distIPs = [x.egressPoint for x in listOfASonPath if
                            (x.egressPoint.hopNum + 1 != self.d_distance and self.d_distance > 0)]
            diff_mplsHopsIPs = [x.egressPoint for x in listOfASonPath if
                                (x.mplsHops != self.d_mplsHops and self.d_mplsHops != '?')]

            self.FIBInconsistencyMetric2 = float(len(set(diff_distIPs).union(set(diff_mplsHopsIPs)))) / self.occ
            self.FIBInconsistencyMetric2ABS = len(set(diff_distIPs).union(set(diff_mplsHopsIPs)))

            # T_mplsTunnelCount != D_mplsTunnelCount
            # 1 vs 0 and 0 vs 1 cases are not considered
            # The only two good cases considered are:
            #     2 for transit vs 1 for direct (in case of Cisco egress - default all in LDP).
            #     2 for transit vs 0 for direct (in case of Juniper egress - default only BGP next hop self in LDP).

            # self.FIBInconsistencyMetric3 = float(sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (k != self.d_mplsTunnelCount and self.d_mplsTunnelCount != "?" and not(k==0 and self.d_mplsTunnelCount==1 or k==1 and self.d_mplsTunnelCount==0) ) ])) / self.occ
            # self.FIBInconsistencyMetric3ABS = sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (k != self.d_mplsTunnelCount and self.d_mplsTunnelCount != "?" and not(k==0 and self.d_mplsTunnelCount==1 or k==1 and self.d_mplsTunnelCount==0) )])

            self.FIBInconsistencyMetric3 = float(sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (
                    k == 2 and self.d_mplsTunnelCount == 1 or k == 2 and self.d_mplsTunnelCount == 0)])) / self.occ
            self.FIBInconsistencyMetric3ABS = sum([self.t_mplsTunnelCountC[k] for k in self.t_mplsTunnelCountC if (
                    k == 2 and self.d_mplsTunnelCount == 1 or k == 2 and self.d_mplsTunnelCount == 0)])

            # T_mplsTunnelCount != D_mplsTunnelCount OR T_dist != D_dist

            # diff_distIPs = [x.egressPoint for x in listOfASonPath if (x.egressPoint.hopNum+1!=self.d_distance and self.d_distance>0)]
            diff_mplsTunnelCountIPs = [x.egressPoint for x in listOfASonPath if (
                    x.mplsTunnelCount == 2 and self.d_mplsTunnelCount == 1 or x.mplsTunnelCount == 2 and self.d_mplsTunnelCount == 0)]

            self.FIBInconsistencyMetric4 = float(len(set(diff_distIPs).union(set(diff_mplsTunnelCountIPs)))) / self.occ
            self.FIBInconsistencyMetric4ABS = len(set(diff_distIPs).union(set(diff_mplsTunnelCountIPs)))


        if dstMDA:
            # dst MDA info here...
            pass

    def get_incfib_vs_te_info(self):
        """
        Calculates the information about subroutes for this CWEgress point.
        """
        #########
        def updateTracesets_internal(tracesets, pathset):
            """
            Duplicated code, once again :-(
            Time for refactoring needed.

            Compares <pathset> with those in <tracesets>.

            Tracesets is a dictionary. path --> set of paths

            There exist 3 cases:
            - pathset overlaps with no sets in tracesets
            - pathset overlaps with only one set in tracesets
            - pathset overlaps with more than one set in tracesets.
            Merges sets in self.tracesets accordingly.
            Add new keys to tracesets.
            """
            overlapping = []  # sets overlapping with pathsets
            allsets = tracesets.values()
            for s in allsets:
                if not s.isdisjoint(pathset):
                    overlapping.append(s)

            if len(overlapping) == 0:
                # no overlap.
                # add a single new set to <tracesets>, with related keys.
                for p in pathset:
                    tracesets[p] = pathset

            elif len(overlapping) == 1:
                # overlap with a single set.
                # update existing set and assign to path in <pathset>
                overlapped = overlapping.pop()
                overlapped.update(pathset)
                for p in overlapped:
                    tracesets[p] = overlapped

            else:  # len(overlapping) > 1:
                # overlap with multiple sets.
                # merge these sets and extend with <pathset>.
                # then assign this new set to each path.
                new = set()
                for s in overlapping:
                    new.update(s)
                new.update(pathset)
                for p in new:
                    tracesets[p] = new
        #####

        dest2routes = dict()
        route2dests = defaultdict(set)
        route2routeset = dict()
        AS = self.AS
        direct_route = self.directTrace.ASInfo[AS].subpath
         
        exp_dstmda_attempts = 0
        dstmda_attempts = 0

        # the list  is expected to have one single IP
        ingressIP = self.t_ingressPointsK[0]


        for x in self.EgressPoints:
            route_set = set()
            destinationIP = x.originatingTrace.destination

            # initial transit subpath:
            transit_route = x.subpath
            route_set.add(transit_route)

            # mda ingresses, if needed
            #mda_ingresses = [x.ingressPoint for x in self.dstMDA.ASOnPathDict[(destinationIP, AS)] if self.dstMDA.ASOnPathDict[(destinationIP, AS)]!=[]]
            #if mda_ingresses:
            #    print "mda"
            #    for ii in mda_ingresses:
            #        print ii
            #    raw_input()

            # additional transit subpaths obtained via destination MDA:
            transit_route_set = [x.subpath for x in self.dstMDA.ASOnPathDict[(destinationIP, AS)]]
            route_set = route_set.union(transit_route_set)
            
            dest2routes[destinationIP] = route_set

            if transit_route != direct_route:
                exp_dstmda_attempts += 1
            if transit_route_set != []:
                dstmda_attempts += 1
        
        for dest in dest2routes:
            for r in dest2routes[dest]:
                route2dests[r].add(dest)

        for dest in dest2routes:
            updateTracesets_internal(route2routeset, dest2routes[dest])
        
        ###################################################
        # test overlaps:
        # If two sets overlap, something is going wrong!
        sets = list(set([frozenset(r) for r in route2routeset.values()]))
        for s in sets:
            other_sets = sets[:]
            other_sets.remove(s)
            for ss in other_sets:
                if not s.isdisjoint(ss):
                    print "[ERROR] partitions are not independent. Something is going wrong!"
                    pprint(s)
                    pprint(ss)
                    sys.exit(1)
        ################################################### 


#        pprint(route2routeset)
#        
#        print len(route2routeset)
#        print len(route2dests)
#        print len(route2routeset.values())
#        print len(set([frozenset(x) for x in route2routeset.values()]))
#        raw_input()
        

        partitions_destnumber = []
        for s in set([frozenset(s) for s in route2routeset.values()]):
            #partitions_destnumber.append(sum([len(route2dests[r]) for r in s]))
            destinations = []
            for r in s:
                destinations.extend(list(route2dests[r]))
            partitions_destnumber.append(len(set(destinations)))

        # each element in the list is True if direct route is included in the set in the same position, false otherwise
        tf_list = [direct_route in y for y in set([frozenset(x) for x in route2routeset.values()])]

        # index of the set containing the direct partition
        direct_partition_index = tf_list.index(True) if True in tf_list else "-"


        ret = {
                "AS" : self.AS,
                "num_traces" : len(dest2routes),
                "num_routes": len(route2dests),
                "num_routes_with_stars": ['q' in x for x in route2dests.keys()].count(True),
                "ingressIP" : ingressIP,
                "egressIP": self.ipAddress,
                "num_partitions": len(set([frozenset(x) for x in route2routeset.values()])),
                "dim_partitions": [len(y) for y in set([frozenset(x) for x in route2routeset.values()])],
                "direct_route_inc": direct_route in route2routeset,
                "direct_partition_size": len(route2routeset[direct_route]) if direct_route in route2routeset else "-",
                "direct_partition_index": direct_partition_index,
                "direct_partition_size_dests": [len(route2dests[r]) for r in route2routeset[direct_route]] if direct_route in route2routeset else "-" ,
                "partitions_size_dests": partitions_destnumber,
                "exp_dstmda_attempts" : exp_dstmda_attempts,
                "dstmda_attempts" : dstmda_attempts
                }  
        

#        pprint(ret)
#        raw_input()
        return ret



    @staticmethod
    def dump_incfib_vs_te_info_header():
        return ";".join(["#{AS}",
                         "{egressIP}",
                         "{num_traces}",
                         "{num_routes}",
                         "{num_routes_with_stars}",
                         "{direct_route_inc}",
                         "{num_partitions}",
                         "{dim_partitions}",
                         "{partitions_size_dests}",
                         "{direct_partition_size}",
                         "{direct_partition_size_dests}",
                         "{dstmda_attempts}",
                         "{exp_dstmda_attempts}",
                         "{ingressIP}",
                         "{direct_partition_index}"
                         ]).format(AS="AS",
                                                     egressIP="egressIP",
                                                     ingressIP="ingressIP",
                                                     num_traces="num_traces/destinations/prefixes",
                                                     num_routes="num distinct transit subroutes",
                                                     num_routes_with_stars="num subroutes containing '*'",
                                                     direct_route_inc="internal subroute included",
                                                     num_partitions="num partitions",
                                                     dim_partitions="partitions size (routes)",
                                                     direct_partition_size="direct partition size (routes)",
                                                     direct_partition_size_dests="direct partition size (dests)",
                                                     partitions_size_dests="partitions size (dests)",
                                                     direct_partition_index="direct_partition_index",
                                                     exp_dstmda_attempts = "exp_dstmda_attempts",
                                                     dstmda_attempts = "dstmda_attempts"
                                                     )

    @staticmethod
    def print_incfib_vs_te_info_header():
        
        print CWEgressPoint2.dump_incfib_vs_te_info_header()
#        print ";".join(["#{AS}",
#                         "{egressIP}",
#                         "{num_traces}",
#                         "{num_paths}",
#                         "{num_paths_with_stars}",
#                         "{direct_route_inc}",
#                         "{num_partitions}",
#                         "{dim_partitions}"]).format(AS="AS",
#                                                     egressIP="egressIP",
#                                                     num_traces="num_traces",
#                                                     num_paths="num_paths",
#                                                     num_paths_with_stars="num_paths_with_stars",
#                                                     direct_route_inc="direct_included",
#                                                     num_partitions="num_partitions",
#                                                     dim_partitions="dim_partitions")

    @staticmethod
    def print_incfib_vs_te_info(ret):
        print CWEgressPoint2.dump_incfib_vs_te_info(ret)

#        print ";".join(["{AS}",
#                         "{egressIP}",
#                         "{num_traces}",
#                         "{num_paths}",
#                         "{num_paths_with_stars}",
#                         "{direct_route_inc}",
#                         "{num_partitions}",
#                         "{dim_partitions}"]).format(**ret)

    @staticmethod
    def dump_incfib_vs_te_info(ret):

        return ";".join(["{AS}",
                         "{egressIP}",
                         "{num_traces}",
                         "{num_routes}",
                         "{num_routes_with_stars}",
                         "{direct_route_inc}",
                         "{num_partitions}",
                         "{dim_partitions}",
                         "{partitions_size_dests}",
                         "{direct_partition_size}",
                         "{direct_partition_size_dests}",
                         "{dstmda_attempts}",
                         "{exp_dstmda_attempts}",
                         "{ingressIP}",
                         "{direct_partition_index}"
                         ]).format(**ret)


    def getASOnPathInfoYYY(self):
        """
        For each (sub)trace (from ingress to egress) associates metrics of interest
        and the outcomes related to their comparison.
        T: number of MPLS tunnels.
        H: number of IP hops (ASLen)
        d: direct trace --- related metrics are the same for traces in the CWEgressPoint, as they refer to the same direct trace.
        t: transit trace
        """

        ECMP_oracle = self.dstMDA.returnECMPOutcome if self.dstMDA else None
        ASOnPathInfo = defaultdict(dict)

        for x in self.EgressPoints:  # EgressPoints is a listOfASonPath

            y = self.directTrace.ASInfo[self.AS]

            AS = AS_t = x.AS
            IN_t = x.ingressPoint.ipAddress
            OUT_t = x.egressPoint.ipAddress
            DST = x.originatingTrace.destination

            AS_d = y.AS
            IN_d = y.ingressPoint.ipAddress
            OUT_d = y.egressPoint.ipAddress

            T_d = y.mplsTunnelCount
            H_d = y.ASLength

            T_t = x.mplsTunnelCount
            H_t = x.ASLength

            OUTrtt_d = self.directTrace.destRTT
            OUTrtt_t = np.average(x.originatingTrace.rttsByIP[OUT_t]) if x.originatingTrace.rttsByIP.has_key(
                OUT_t) else 0

            destReplied = y.originatingTrace.destReplied == "R"

            subpathsMatch = "S" if x.subpath == y.subpath else "D"
            sub_t = ",".join(x.subpath)
            sub_d = ",".join(y.subpath)

            # N: NOT REPLYING - egress point did not replied
            # U: UNCONCLUSIVE - subpaths containts "*"
            # E: EMPTY - 0vs0
            # I: winning cases, i.e., 2vs1 or 2vs0
            # C: (n,n) for n > 0
            # O: other

            E_set = [(0, 0)]
            I_set = [(2, 0), (2, 1)]
            C_set = [(n, n) for n in range(1, 21)]


            if destReplied:

                M_H = ">" if H_d > H_t else "<" if H_d < H_t else "="

                M_T = "U" if x.containsStars else \
                    "E" if (T_t, T_d) in E_set else \
                        "I" if (T_t, T_d) in I_set else \
                            "C" if (T_t, T_d) in C_set else \
                                "O"
            else:
                M_T = "N"
                M_H = "N"

            if OUTrtt_t != 0 and OUTrtt_d != 0:
                M_RTT = OUTrtt_t - OUTrtt_d
            else:
                M_RTT = "N"

            if IN_t != IN_d or AS_t != AS_d or OUT_t != y.originatingTrace.destination:
                print "SOMETHING WRONG!!!"
                print IN_t
                print IN_d
                print AS_t
                print AS_d
                print OUT_t
                print y.originatingTrace.destination
                raw_input()


            ECMP_outcome = ECMP_oracle(x.subpath, y.subpath, DST, AS) if ECMP_oracle else None

            # DBG
#            if ECMP_outcome == "SAME" and M_H != "=":
#                print sub_t
#                print sub_d
#                print x.originatingTrace
#                print self.directTrace
#                print H_t
#                print H_d
#                print M_H
#                print x.originatingTrace.rawInput
#                print self.directTrace.rawInput
#                raw_input()
#            print DST, AS, ECMP_outcome

            ASOnPathInfo[(AS, OUT_t, IN_t, DST)] = {"AS": AS,
                                                    "OUT": OUT_t,
                                                    "IN": IN_t,
                                                    "DST": DST,
                                                    "M_H": M_H,
                                                    "M_T": M_T,
                                                    "H_t": H_t,
                                                    "H_d": H_d,
                                                    "T_t": T_t,
                                                    "T_d": T_d,
                                                    "OUTrtt_t": OUTrtt_t,
                                                    "OUTrtt_d": OUTrtt_d,
                                                    "M_RTT": M_RTT,
                                                    "subpathsMatch": subpathsMatch,
                                                    "sub_t": sub_t,
                                                    "sub_d": sub_d,
                                                    "ECMP" : ECMP_outcome
                                                    }

        return ASOnPathInfo

    #                print x.originatingTrace
    #                print
    #                print y.originatingTrace
    #
    #                print AS_t == AS_d
    #                print IN_t == IN_d
    #                print OUT_t == OUT_d
    #
    #                print "", OUT_t
    #                print "", OUT_d
    #
    #                print "T_d", T_d
    #                print "T_t", T_t
    #
    #                print "H_d", H_d
    #                print "H_t", H_t
    #
    #                if H_t != H_d:
    #                    raw_input()

    def __compareDistance(self, dd, tds):
        """
        compare direct distance towards an egress point against (the maximum) if transit distances.
        returns "?" if direct distance is not available.
        """
        ret = "?" if dd == 0 else "<" if dd < max(tds) else "=" if dd == max(tds) else ">"
        return ret

    def __compare2(self, dd, tds):
        """
        Same as compareDistance, but does not consider dd=0 as a special value.
        It is used for comparintg other metrics (e.g., ASHops, MPLS hops)
        """
        ret = "<" if dd < max(tds) else "=" if dd == max(tds) else ">"
        return ret

    def __removePathsWithStars(self, pathList):
        newPathList = []
        for t in pathList:
            if not "q" in t:
                newPathList.append(t)
        return newPathList

    def findTransitSubPaths(self, removePathsWithStars=False):
        """
        Finds the set of Direct paths from ingress(es) to the egress to related transit subpaths.
        And sets related info.
        """

        mdaTrace = self.directMDATrace

        egressIP = self.ipAddress
        transitSubPaths = []
        ingressIPs = []
        for x in self.EgressPoints:
            ingressIP = x.ingressPoint.ipAddress  # ASOnPaths could have different ingress point
            try:
                # print x.originatingTrace
                # print "EGR", egressIP
                # print "ING", ingressIP
                transitSubPath = x.originatingTrace.getSubTrace(ingressIP, egressIP)
                transitSubPaths.append(transitSubPath)
            except IpNotOnPathException, e:  # e.g., in case of non-replying egress
                print e
                raw_input()

        if removePathsWithStars:
            transitSubPaths = self.__removePathsWithStars(transitSubPaths)
        if len(transitSubPaths) == 0:
            raise AllPathsWithStarsException(
                "All transit subpaths from %s to %s contains at least a '*'" % (ingressIP, egressIP))
        self.transitSubPathsSet = set(transitSubPaths)
        self.transitSubPathsC = Counter(transitSubPaths)
        self.transitSubPathsOcc = self.transitSubPathsC.values()
        self.transitSubPathsCard = len(self.transitSubPathsSet)

    def findMDAdirectSubPaths(self, removePathsWithStars=False):
        """
        Finds the set of MDA paths from ingress(es) to the egress to related transit subpaths.
        And sets related info.
        """
        mdaTrace = self.directMDATrace
        egressIP = self.ipAddress
        mdaSubPaths = []
        for ingressIP in set(self.t_ingressPointsK):
            try:
                mdaSubPaths.extend(mdaTrace.getSimplePaths(ingressIP, egressIP))
            except IpNotOnPathException, e:
                raise IpNotOnPathException(e)
                # print mdaTrace.destination
                # print mdaTrace.G.edges()
                # raw_input()

        if removePathsWithStars:
            mdaSubPaths = self.__removePathsWithStars(mdaSubPaths)
        if len(mdaSubPaths) == 0:
            raise AllPathsWithStarsException(
                "All MDA direct subpaths from %s to %s contains at least a '*'" % (ingressIP, egressIP))
        self.hasMDAdirectSubPath = True
        self.MDAdirectSubPathsSet = set(map(tuple, mdaSubPaths))
        self.MDAdirectSubPathsC = Counter(mdaSubPaths)
        self.MDAdirectSubPathsOcc = self.MDAdirectSubPathsC.values()
        self.MDAdirectSubPathsCard = len(self.MDAdirectSubPathsSet)

    def evaluateOverlap(self):
        """
        Compares the set of MDA paths from ingress(es) to the egress to related transit subpaths.
        """
        TisSubset = self.transitSubPathsSet < self.MDAdirectSubPathsSet
        DisSubset = self.MDAdirectSubPathsSet < self.transitSubPathsSet
        Congruent = self.transitSubPathsSet == self.MDAdirectSubPathsSet
        Disjoint = self.transitSubPathsSet.isdisjoint(self.MDAdirectSubPathsSet)

        self.mdadt_overlap = "TisSubset" if TisSubset else \
            "DisSubset" if DisSubset else \
                "Congruent" if Congruent else \
                    "Disjoint" if Disjoint else \
                        "Intersected"

        strictlyOverlappingPaths = 0
        for p1 in self.MDAdirectSubPathsSet:
            if True in [evaluatePathMatch(p1, x, strict=True) for x in self.transitSubPathsSet]:
                strictlyOverlappingPaths += 1

        looselyOverlappingPaths = 0
        for p1 in self.MDAdirectSubPathsSet:
            if True in [evaluatePathMatch(p1, x, strict=False) for x in self.transitSubPathsSet]:
                looselyOverlappingPaths += 1

        self.strictlyOverlappingPathsNum = strictlyOverlappingPaths
        self.looselyOverlappingPathsNum = looselyOverlappingPaths

    def DTVector(self):
        # (D?TASPath, D?TIngressPoints, TDistanceStability, D?TDistance, TASHopsStability, D?TASHops, TMPLSHopsStability, D?TMPLSHops)
        return (
            self.dt_ASSeq, self.dt_ingressPoint, self.t_distanceStability, self.dt_distance, self.t_ASLengthStability,
            self.dt_ASLength, self.t_mplsHopsStability, self.dt_mplsHops)

    @staticmethod
    def translateCode(code):

        diz = {
            CWEgressPoint.BGPDETOUR: "BGPDETOUR",
            CWEgressPoint.DIFFERENTINGRESS: "DIFFERENTINGRESS",
            CWEgressPoint.ALLTHESAME: "ALLTHESAME",
            CWEgressPoint.ALLTHESAME_SHORTERMPLSTUNNEL: "ALLTHESAME_SHORTERMPLSTUNNEL",
            CWEgressPoint.INCFIB1_SHORTERMPLSTUNNEL: "INCFIB1_SHORTERMPLSTUNNEL",
            CWEgressPoint.INCFIB2_LONGERMPLSTUNNEL: "INCFIB2_LONGERMPLSTUNNEL",
            CWEgressPoint.INCFIB3_SAMELENGTHMPLSTUNNEL: "INCFIB3_SAMELENGTHMPLSTUNNEL",
            CWEgressPoint.MULTIPLEINGRESSES: "MULTIPLEINGRESSES*",
            CWEgressPoint.ECMP: "ECMP",
            CWEgressPoint.TRANSITCANBESHORTER: "TRANSITCANBESHORTER",
            CWEgressPoint.TRANSITALWAYSSHORTER: "TRANSITALWAYSSHORTER",
            CWEgressPoint.SPURIOUS1: "SPURIOUS1",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.SPURIOUS2: "SPURIOUS2",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.SPURIOUS3: "SPURIOUS3",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.SPURIOUS4: "SPURIOUS4",  # destination-based loadbalancing?  routing-change?
            CWEgressPoint.NOLLOSO: "UNKNOWN"
        }

        return diz[code]

    BGPDETOUR = 0
    DIFFERENTINGRESS = 1
    ALLTHESAME = 2
    ALLTHESAME_SHORTERMPLSTUNNEL = 3
    INCFIB1_SHORTERMPLSTUNNEL = 4
    INCFIB2_LONGERMPLSTUNNEL = 5
    MULTIPLEINGRESSES = 6
    INCFIB3_SAMELENGTHMPLSTUNNEL = 7
    ECMP = 8
    TRANSITALWAYSSHORTER = 9
    TRANSITCANBESHORTER = 10
    SPURIOUS1 = 11
    SPURIOUS2 = 12
    SPURIOUS3 = 13
    SPURIOUS4 = 14
    NOLLOSO = 999

    def classification(self):

        if self.dt_ASSeq == "D":
            return self.BGPDETOUR

        if self.dt_ingressPoint == "D":
            return self.DIFFERENTINGRESS

        if self.dt_ingressPoint == "I":
            return self.MULTIPLEINGRESSES

        #        if self.dt_ASSeq == "S"                                     and\
        #           self.dt_ingressPoint == "S"                              and\
        #           self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL and\
        #           self.t_percMaxDistance < 55 and\
        #           self.t_percMaxDistance > 45:
        #            return self.ECMP
        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == ">" and \
                self.dt_ASLength == "=":
            return self.SPURIOUS1

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "=":
            return self.SPURIOUS2

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "=" and \
                self.dt_ASLength == ">":
            return self.SPURIOUS3

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "<":
            return self.SPURIOUS4

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "=":
            return self.TRANSITCANBESHORTER

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == ">" and \
                self.dt_ASLength == ">":
            return self.TRANSITALWAYSSHORTER

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.t_distanceStability == CWEgressPoint.STABLE_LABEL and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "=" and \
                self.dt_mplsHops == "=":
            return self.ALLTHESAME

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.t_distanceStability == CWEgressPoint.STABLE_LABEL and \
                self.dt_distance == "=" and \
                self.dt_ASLength == "=" and \
                self.dt_mplsHops == "<":
            return self.ALLTHESAME_SHORTERMPLSTUNNEL

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "<" and \
                self.dt_mplsHops == "<":
            return self.INCFIB1_SHORTERMPLSTUNNEL
        # self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL   and\

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "<" and \
                self.dt_mplsHops == ">":
            return self.INCFIB2_LONGERMPLSTUNNEL
        # self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL   and\

        if self.dt_ASSeq == "S" and \
                self.dt_ingressPoint == "S" and \
                self.dt_distance == "<" and \
                self.dt_ASLength == "<" and \
                self.dt_mplsHops == "=":
            return self.INCFIB3_SAMELENGTHMPLSTUNNEL
        # self.t_distanceStability == CWEgressPoint.VARIABLE_LABEL   and\

        else:
            return self.NOLLOSO

    @staticmethod
    def toLineHeader():
        return ";".join([
            "{AS}",
            "{ip}",
            "{fqdn}",
            "{occ}",
            "{incscore}",
            "{incscore2}",
            "{tdiststab}",
            "{tdist}",
            "{tdistocc}",
            "{percMaxDistance}",
            "{ddist}",
            "{tmplshopsstab}",
            "{tmplshops}",
            "{tmplshopsocc}",
            "{percMaxMplsHops}",
            "{dmplshops}",
            "{tashopsstab}",
            "{tashops}",
            "{tashopsocc}",
            "{percMaxASHops}",
            "{dashops}",
            "{t_ingress}",
            "{t_ingressocc}",
            "{d_ingress}",
            "{d_t_dist}",
            "{d_t_aspath}",
            "{d_t_ingress}",
            "{d_t_ashops}",
            "{d_t_mplshops}",
            "{classification}"]).format(
            AS="ASN",
            ip="IP",
            fqdn="FQDN",
            occ="Occurrences", \
 \
            d_t_dist="D?T Distance",
            d_t_aspath="D?T AS Path",
            d_t_ingress="D?T Ingress Points",
            d_t_ashops="D?T AS Hops",
            d_t_mplshops="D?T MPLS Hops", \
 \
            tdiststab="Transit Distance Stability",
            tdistocc="Transit Distance Occurrences",
            tdist="Transit Distance",
            ddist="Direct Distance", \
 \
            tmplshopsstab="Transit MPLS Hops Stability",
            tmplshopsocc="Transit MPLS Hops Occurrences",
            tmplshops="Transit MPLS Hops",
            dmplshops="Direct MPLS Hops", \
 \
            tashopsstab="Transit Hops in AS Stability",
            tashopsocc="Transit Hops in AS Occurrences",
            tashops="Transit Hops in AS",
            dashops="Direct Hops in AS", \
 \
            t_ingress="Transit Ingress Points",
            t_ingressocc="Transit Ingress Points Occurrences",
            d_ingress="Direct Ingress Point", \
 \
            classification="Classification",
            percMaxASHops="% max AS Hops",
            percMaxMplsHops="% max MPLS Hops",
            percMaxDistance="% max Distance",
            incscore="Fraction of Transit Paths longer than the Direct Path (LONGER DISTANCE)",
            incscore2="Fraction of Transit Paths with DIFFERENT DISTANCE OR DIFFERENT MPLSHOPS than the Direct Path"
        )

    #    @staticmethod
    #    def toLineHeader():
    #        return "{AS};{ip};{fqdn};{occ};\
    # {incscore};{incscore2};\
    # {tdiststab};{tdist};{tdistocc};{percMaxDistance};{ddist};\
    # {tmplshopsstab};{tmplshops};{tmplshopsocc};{percMaxMplsHops};{dmplshops};\
    # {tashopsstab};{tashops};{tashopsocc};{percMaxASHops};{dashops};\
    # {t_ingress};{t_ingressocc};{d_ingress};\
    # {d_t_dist};{d_t_aspath};{d_t_ingress};{d_t_ashops};{d_t_mplshops};\
    # {classification};".format(
    #                                            AS="ASN",
    #                                            ip="IP",
    #                                            fqdn="FQDN",
    #                                            occ="Occurrences",
    #                                            \
    #                                            d_t_dist="D?T Distance",
    #                                            d_t_aspath="D?T AS Path",
    #                                            d_t_ingress="D?T Ingress Points",
    #                                            d_t_ashops="D?T AS Hops",
    #                                            d_t_mplshops="D?T MPLS Hops",
    #                                            \
    #                                            tdiststab="Transit Distance Stability",
    #                                            tdistocc="Transit Distance Occurrences",
    #                                            tdist="Transit Distance",
    #                                            ddist="Direct Distance",
    #                                            \
    #                                            tmplshopsstab="Transit MPLS Hops Stability",
    #                                            tmplshopsocc="Transit MPLS Hops Occurrences",
    #                                            tmplshops="Transit MPLS Hops",
    #                                            dmplshops="Direct MPLS Hops",
    #                                            \
    #                                            tashopsstab="Transit Hops in AS Stability",
    #                                            tashopsocc="Transit Hops in AS Occurrences",
    #                                            tashops="Transit Hops in AS",
    #                                            dashops="Direct Hops in AS",
    #                                            \
    #                                            t_ingress="Transit Ingress Points",
    #                                            t_ingressocc="Transit Ingress Points Occurrences",
    #                                            d_ingress="Direct Ingress Point",
    #                                            \
    #                                            classification="Classification",
    #                                            percMaxASHops="% max AS Hops",
    #                                            percMaxMplsHops="% max MPLS Hops",
    #                                            percMaxDistance="% max Distance",
    #                                            incscore="Fraction of Transit Paths longer than the Direct Path (LONGER DISTANCE)",
    #                                            incscore2="Fraction of Transit Paths with DIFFERENT DISTANCE OR DIFFERENT MPLSHOPS than the Direct Path"
    #                                            )

    def toLine(self):
        return ";".join(["{AS}",
                         "{ip}",
                         "{fqdn}",
                         "{occ}",
                         "{incscore:.2f}",
                         "{incscore2:.2f}",
                         "{tdiststab}",
                         "{tdist}",
                         "{tdistocc}",
                         "{percMaxDistance:.2f}",
                         "{ddist}",
                         "{tmplshopsstab}",
                         "{tmplshops}",
                         "{tmplshopsocc}",
                         "{percMaxMplsHops:.2f}",
                         "{dmplshops}",
                         "{tashopsstab}",
                         "{tashops}",
                         "{tashopsocc}",
                         "{percMaxASHops:.2f}",
                         "{dashops}",
                         "{t_ingress}",
                         "{t_ingressocc}",
                         "{d_ingress}",
                         "{d_t_dist}",
                         "{d_t_aspath}",
                         "{d_t_ingress}",
                         "{d_t_ashops}",
                         "{d_t_mplshops}",
                         "{classification}"]).format(
            AS=self.AS,
            ip=self.ipAddress,
            fqdn=reverseDNS(self.ipAddress),
            occ=self.occ, \
 \
            d_t_dist=self.dt_distance,
            d_t_aspath=self.dt_ASSeq,
            d_t_ingress=self.dt_ingressPoint,
            d_t_ashops=self.dt_ASLength,
            d_t_mplshops=self.dt_mplsHops, \
 \
            tdiststab=self.t_distanceStability,
            tdistocc=self.t_distanceOcc,
            tdist=self.t_distanceK,
            ddist=self.d_distance, \
 \
            tmplshopsstab=self.t_mplsHopsStability,
            tmplshopsocc=self.t_mplsHopsOcc,
            tmplshops=self.t_mplsHopsK,
            dmplshops=self.d_mplsHops, \
 \
            tashopsstab=self.t_ASLengthStability,
            tashopsocc=self.t_ASLengthOcc,
            tashops=self.t_ASLengthK,
            dashops=self.d_ASLength, \
 \
            d_ingress=self.d_ingressPoint,
            t_ingress=self.t_ingressPointsK,
            t_ingressocc=self.t_ingressPointsOcc, \
 \
            classification=CWEgressPoint.translateCode(self.classification()),
            percMaxASHops=self.t_percMaxASLength,
            percMaxMplsHops=self.t_percMaxMplsHops,
            percMaxDistance=self.t_percMaxDistance,
            incscore=self.FIBInconsistencyMetric,
            incscore2=self.FIBInconsistencyMetric2
        )

    def toLine2(self):

        return ";".join([
            "{overlap}",
            "{strictlyoverlapping}",
            "{looselyoverlapping}",
            "{intersectionsize}",
            "{intersectionocc}",
            "{transitcount}",
            "{transitocc}",
            "{directmdacount}",
            "{directmdaocc}"]).format(overlap=self.mdadt_overlap if self.mdadt_overlap else "?",
                                      transitcount=self.transitSubPathsCard,
                                      transitocc=self.transitSubPathsOcc,
                                      directmdacount=self.MDAdirectSubPathsCard if self.hasDirectMDATrace else "?",
                                      directmdaocc=self.MDAdirectSubPathsOcc if self.hasDirectMDATrace else "?",
                                      intersectionsize=len(self.transitSubPathsSet.intersection(
                                          self.MDAdirectSubPathsSet)) if self.hasMDAdirectSubPath else "?",
                                      intersectionocc=[self.transitSubPathsC[x] for x in
                                                       self.transitSubPathsSet.intersection(
                                                           self.MDAdirectSubPathsSet)] if self.hasMDAdirectSubPath else "?",
                                      strictlyoverlapping=self.strictlyOverlappingPathsNum,
                                      looselyoverlapping=self.looselyOverlappingPathsNum)

    @staticmethod
    def toLine2Header():
        return ";".join(["{overlap}",
                         "{strictlyoverlapping}",
                         "{looselyoverlapping}",
                         "{intersectionsize}",
                         "{intersectionocc}",
                         "{transitcount}",
                         "{transitocc}",
                         "{directmdacount}",
                         "{directmdaocc}"]).format(overlap="Overlap outcome",
                                                   transitcount="Different transit subpaths",
                                                   transitocc="Transit subpaths occurrences",
                                                   directmdacount="MDA direct subpaths",
                                                   directmdaocc="MDA direct subpaths occurrences",
                                                   intersectionsize="Overlap size",
                                                   intersectionocc="Overlap occurrences",
                                                   strictlyoverlapping="Stricly Overlapping Paths",
                                                   looselyoverlapping="Loosely Overlapping Paths")

    def excludeDistanceOutliers(self, thresh=1):
        """
        Excludes egress points occurrences with distances whose occurrence is less than <thresh>% of the total (if any).
        These cases are due to route flapping.
        """

        perc = map(lambda x: float(x) * 100 / self.occ, self.t_distanceC.values())
        valsToRemove = [self.t_distanceC.keys()[i] for i in [perc.index(x) for x in perc if x <= thresh]]

        # if there are occurrences to be removed, call again the contructor
        if valsToRemove != []:
            listOfASonPath = [x for x in self.EgressPoints if
                              x.egressPoint.hopNum + 1 not in valsToRemove]  # remove egress points with distance in valsToRemove
            self = self.__init__(listOfASonPath, self.directTrace, self.dstMDA,
                                 excludeNoisy=self.excludeNoisy)  # update data structures

    def excludeDifferentIngressPoints(self):
        """
        Excludes egress points when the ingress point is different than that of the Direct Trace.
        """
        listOfASonPath = [x for x in self.EgressPoints if x.ingressPoint.ipAddress == self.d_ingressPoint]

        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllDifferentIngressException(
                "No occurrence entering the AS through %s for this CW Egress Point: %s" % (
                    self.d_ingressPoint, self.ipAddress))
        else:
            self = self.__init__(listOfASonPath, self.directTrace, self.dstMDA,
                                 excludeNoisy=self.excludeNoisy)  # update data structures

    def excludeDifferentASSeqs(self):
        """
        Exclude egress points whose path crossed different AS Sequences.
        """

        listOfASonPath = [x for x in self.EgressPoints if tuple(
            x.originatingTrace.ASSequence[:x.originatingTrace.ASSequence.index(self.AS) + 1]) == self.d_ASSeq]

        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllDifferentASPathException(
                "No occurrence crossing %s for this CW Egress Point: %s" % (self.d_ASSeq, self.ipAddress))
        else:
            self = self.__init__(listOfASonPath, self.directTrace, self.dstMDA,
                                 excludeNoisy=self.excludeNoisy)  # update data structures

    def excludeUnderSampled(self, thresh):
        """
        Raises exception if self.occ < thresh.
        """

        if self.occ < thresh:
            # when all egress points are noisy, raise exception
            raise UnderSampledException("Only %s occurrences (less than %s) left for this CW Egress Point: %s" % (
                self.occ, thresh, self.ipAddress))

    def excludeShortASes(self, minLength=3):
        """
        Excludes egress points occurrences with ASLength shorter than minLenght (if any).
        These cases are potentially due to HIDDEN tunnels.
        """

        listOfASonPath = [x for x in self.EgressPoints if
                          x.ASLength >= minLength]  # remove egress points in ASes shorter than minLength

        if listOfASonPath == []:
            self.allNoisy = True
            # when all egress points are noisy, raise exception
            raise AllShortException(
                "No occurrence longer than %s left for this CW Egress Point %s" % (minLength, self.ipAddress))
        else:
            self = self.__init__(listOfASonPath, self.directTrace, self.dstMDA,
                                 excludeNoisy=self.excludeNoisy)  # update data structures


def evaluatePathMatch(p1, p2, strict=True):
    """
    compares two paths.
    returns True if the are the same, false otherwise
    """

    if len(p1) != len(p2):
        return False
    else:
        for i in range(0, len(p1)):
            if p1[i] != p2[i]:
                if strict == True:
                    return False
                else:
                    if p1[i].startswith("q") or p2[i].startswith("q") or p1[i].startswith("*") or p2[i].startswith("*"):
                        continue
                    else:
                        return False
        return True


class ASOnPath:
    """
    ASOnPath represents the occurrence of an AS (i.e. a sequence of consecutive hops with specific characteristics) on a given path.
    """

    # TODO note that in case of ASOnPath ending at the destination, the ipgressPoint.ipAdddress
    # does not match with the destination. The metrics are correct, though.
    def __init__(self, ingressPoint, egressPoint, originatingTrace, AS):
        self.ingressPoint = ingressPoint
        self.egressPoint = egressPoint
        self.originatingTrace = originatingTrace
        self.skipped1st = False
        self.AS = AS

        self.__evaluate_internals()


    def __evaluate_internals(self):
        self.ASLength = self.egressPoint.hopNum - self.ingressPoint.hopNum + 1
        self.mplsHops = self.originatingTrace.mplsHopsBefore(self.egressPoint.hopNum) - self.originatingTrace.mplsHopsBefore(
            self.ingressPoint.hopNum - 1)


        # MPLS tunnel calculation (count and length)
        mplsLabelsInThisAS = [self.originatingTrace.mplsInfo[x] != {} for x in self.originatingTrace.mplsInfo if
                              (x >= self.ingressPoint.hopNum and x <= self.egressPoint.hopNum)]
        groups = groupby(mplsLabelsInThisAS)
        result = [(label, sum(1 for _ in group)) for label, group in groups]
        self.mplsTunnelLengths = [x[1] for x in result if x[0] == True]
        self.mplsTunnelCount = len(self.mplsTunnelLengths)

        subpath = self.originatingTrace.hops.values()[self.ingressPoint.hopNum: self.egressPoint.hopNum + 1]

        #        if AS == self.originatingTrace.destinationAS and self.originatingTrace.destReplied == 'R':
        #            self.ASLength += 1  # if AS is the destinationAS and dest replied, ASLength is increased by one. This is needed for properly computing AS length in Direct traces.

        # set([len(x) for x in self.subpath])

        subpath = [x[0] for x in
                   subpath]  # in case of multiple IP addresses of a given hop, just considers the first one

        if self.AS == self.originatingTrace.destinationAS and self.originatingTrace.destReplied == 'R':
            self.ASLength = (self.originatingTrace.destDistance - 1) - self.ingressPoint.hopNum + 1
            subpath.append(self.originatingTrace.destination)
            # if AS is the destinationAS and dest replied, ASLength is increased by one and the destination IP is appended to the subpath.
            # This is needed for properly computing AS length in Direct traces.
            # cases have been found for which dest distance more than +1 (MPLS PHP?), so we refer to destination distance instead of simply adding 1

        self.subpath = tuple(subpath)

        self.containsStars = 'q' in self.subpath
        self.isNoisy = self.ingressPoint.isNoisy or self.egressPoint.isNoisy

    def skiphops(self, nhops):
        if not self.ASLength > nhops+1:  # nhops+2 hops needed to skip number hops.
            # Indeed nhop+1 is enough, but the implementation is easier this way (no need to deal with destination)
            # (ASes Shorter than 3 would be discarded in the following)
            raise CannotSkipHops("Cannot skip {} hop(s), ASlength={}".format(nhops, self.ASLength))


        if not self.skipped1st:
            try:
                newIngress = IngressPoint(self.originatingTrace.hops[self.ingressPoint.hopNum + nhops][0],
                                      self.ingressPoint.AS,
                                      self.ingressPoint.ipAddress,
                                      self.ingressPoint.prevAS,
                                      self.ingressPoint.hopNum + nhops)
            except KeyError:
                # In limited cases the desitnation appears at a distance greater than previous_hop+1.
                # In these cases based on AS lenth the algoritm tries to skip nodes and generates a Key error
                # these cases are managed such to raise the same exception as above
                raise CannotSkipHops("Cannot skip {} hop(s), ASlength={}\n{}".format(nhops, self.ASLength, self.originatingTrace))

            self.ingressPoint = newIngress
            self.__evaluate_internals()
            self.skipped1st = True


    def skip1sthop(self):
        self.skiphops(1)

class CannotSkipHops(Exception):
    pass

class MDATraceCampaign:
    """
    List of MDA traces.
    (data source: paris traceroute MDA - scamper implementation)
    """

    def __init__(self, campaignFile):
        """
        Divides the campaignFile in slices, each passed to MDATrace constructor.
        """

        self.traces = []
        self.tracesByDestination = {}
        with open(campaignFile) as f:
            lines = f.readlines()
        borderIndexes = [i for i in range(0, len(lines)) if lines[i].startswith("tracelb")]
        for iborder in range(0, len(borderIndexes)):
            start = borderIndexes[iborder]
            try:
                stop = borderIndexes[iborder + 1]
            except IndexError, e:
                # print e
                stop = len(lines)

            mdaTrace = MDATrace(lines[start:stop])
            self.traces.append(mdaTrace)
            self.tracesByDestination[mdaTrace.destination] = mdaTrace


#        for t in self.traces:
#            t.remapFirstSTRStar()
#            print "DEST", t.destination
#            try:
#                pprint(t.getSimplePaths("193.51.183.130", t.destination))
#                raw_input()
#            except IpNotOnPathException, e:
#                print e
#                raw_input()
#
#            try:
#                pprint(t.getSimplePaths("129.143.19.121", t.destination))
#                raw_input()
#            except IpNotOnPathException, e:
#                print e
#                raw_input()


class MDATrace:
    """
    Each object is an MDA trace.
    (data source: paris traceroute MDA - scamper implementation)
    """

    def __init__(self, lines):
        def translateStars(ip):
            ip = ip.strip()
            if ip == "*":
                retVal = "q%d" % self.qCounter
                self.qCounter += 1
            elif "*" in ip:  # e.g., "(129.250.2.44, *)"
                retVal = ip.split(",")[0].strip("(")
            else:
                retVal = ip
            return retVal

        self.scamperRawLines = lines
        self.qCounter = 0

        header = lines[0]
        body = lines[1:]

        self.source = header.split("from")[1].split()[0].strip()
        self.destination = header.split("to")[1].split(",")[0].strip()

        self.G = nx.DiGraph()
        for line in body:
            splitLines = line.split("->")
            splitLines = map(translateStars, splitLines)

            for i in range(0, len(splitLines) - 1):
                self.G.add_edge(splitLines[i], splitLines[i + 1])

    def remapFirstSTRStar(self):
        # DANGER!!!!!
        ordered = list(nx.topological_sort(self.G))

        if len(ordered) >= 3 and ordered[2] == "q0":
            mapping = {"q0": "193.51.183.130"}
            self.G = nx.relabel_nodes(self.G, mapping, copy=False)

    #        print self.G.nodes()
    #        print self.G.edges()
    #
    #        head = list(nx.topological_sort(self.G))[0]
    #
    #        print head
    #
    #        #head = nx.topological_sort(self.G)
    #        try:
    #            pprint (list(nx.all_simple_paths(self.G, head, self.destination)))
    #        except nx.exception.NodeNotFound:
    #            print "node not found!!"
    #
    #        raw_input()

    def getSimplePaths(self, source, target, translateStarsBack=True):
        """
        Returns the list of paths from source to target.
        Raise nx.exception.NodeNotFound if source or destination are not in the trace.
        """

        def translateStarsBackFun(tup):
            """
            Replaces "q<number>" with "q".
            It is needed for comparing paths with stars.
            """
            l = list(tup)
            for i in range(0, len(l)):
                if l[i].startswith("q"):
                    l[i] = "q"
            return tuple(l)

        try:
            paths = list(nx.all_simple_paths(self.G, source, target))
            if translateStarsBack:
                paths = map(translateStarsBackFun, paths)
        except nx.exception.NodeNotFound, e:
            raise IpNotOnPathException(e)
        return paths


class IP2ASMapper:
    """
    The mapper takes pfx2as file as input and implements ip2as mapping services.
    bdrmapit output is also supported.
    """

    PFX2AS_FORMAT = "PFX2AS"
    BDRMAPIT_FORMAT = "BDRMAPIT"

    def __init__(self, filename, format=PFX2AS_FORMAT):

        self.format = format
        self.mapInfoBase = self.buildMapInfoBase(filename)


    def buildMapInfoBase(self, filename):
        if self.format == IP2ASMapper.PFX2AS_FORMAT:
            return self.buildMapInfoBase_pfx2as(filename)
        elif self.format == IP2ASMapper.BDRMAPIT_FORMAT:
            return self.buildMapInfoBase_bdrmapit(filename)


    def buildMapInfoBase_pfx2as(self, filename):
        """
        Builds a mapping information base leveraging radixtree.
        """
        mapInfoRawBase = parsePfx2as(filename)
        print(len(mapInfoRawBase))
        mapInfoBase = radix.Radix()

        for t in mapInfoRawBase:
            pfx, pfxLen, AS = t
            node = mapInfoBase.add("%s/%s" % (pfx, pfxLen))
            node.data["AS"] = AS
        return mapInfoBase


    def buildMapInfoBase_bdrmapit(self, filename):
        """
        Reads the sqllite3 file provided by bdrmapit and return a dict: ip --> as
        """

        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        connection = sqlite3.connect(filename)
        connection.row_factory = dict_factory
        cursor = connection.cursor()
        cursor.execute("select * from annotation")
        results = cursor.fetchall()
        # mapInfoBase = {str(x["addr"]): str(x["asn"]) for x in results}

        mapInfoRawBase = [(str(x["addr"]), 32, str(x["asn"])) for x in results]
        mapInfoBase = radix.Radix()
        for t in mapInfoRawBase:
            pfx, pfxLen, AS = t
            node = mapInfoBase.add("%s/%s" % (pfx, pfxLen))
            node.data["AS"] = AS
        return mapInfoBase

    def mapIP(self, ipAddress):
        if self.format == IP2ASMapper.PFX2AS_FORMAT:
            return self.mapIP_pfx2as(ipAddress)
        elif self.format == IP2ASMapper.BDRMAPIT_FORMAT:
            return self.mapIP_bdrmapit(ipAddress)


    def mapIP_pfx2as(self, ipAddress):
        """
        Performs IP2AS mapping leveraging the information base that uses radixtree.
        """
        if ipAddress == 'q':
            return 'q'
        node = self.mapInfoBase.search_best(ipAddress)
        if node is not None:
            return node.data["AS"]
        else:
            if ipaddress.ip_address(unicode(ipAddress)).is_private:
                return "Private"
            else:
                return None


    def mapIP_bdrmapit(self, ipAddress):
        """
        Performs IP2AS mapping leveraging  the dict containing bdrmapit info
        """
        if ipAddress == 'q':
            return 'q'
        if ipAddress in self.mapInfoBase:
            return self.mapInfoBase[ipAddress]
        else:
            if ipaddress.ip_address(unicode(ipAddress)).is_private:
                return "Private"
            else:
                return None


    def buildMapInfoBase2(self, filename):
        """
        DEPRECATED! - the alternative version perfoms way better!
        Build a mapping information base leveraging the ipaddress module.
        """
        mapInfoRawBase = parsePfx2as(filename)
        mapInfoBase2 = []
        for t in mapInfoRawBase:
            pfx, pfxLen, AS = t
            net = ipaddress.ip_network(unicode("%s/%s" % (pfx, pfxLen)))  # ip_network requires unicode strings as input
            t = (net, AS)
            mapInfoBase2.append(t)
        return mapInfoBase2


    def mapIP2(self, ipAddress):
        """
        DEPRECATED! - the alternative version perfoms way better!
        Performs IP2AS mapping leveraging the information base that uses the ipaddress module.
        """
        mappingList = [x for x in self.mapInfoBase2 if
                       ipaddress.ip_address(unicode(ipAddress)) in x[0]]  # list of prefixes matching
        if len(mappingList) == 0:
            return None
        if len(mappingList) > 1:
            mappingList.sort(key=lambda variable: variable[0].prefixlen,
                             reverse=True)  # the list is ordered (desc) according to the length of the prefixes
        return mappingList.pop()[1]


def analyzeCampaignXXX(campaignFile, mapperFile, toEgressCampaignFile=None, toEgressMDACampaignFile=None, nickname=None,
                       traceFormat=Trace.SCAMPER_FORMAT, mapperFormat=IP2ASMapper.PFX2AS_FORMAT):
    """
    """

    if nickname:
        print "::::::::::::::::::::::::\n:: CAMPAIGN: %s\n::::::::::::::::::::::::\n" % nickname
    mapper = IP2ASMapper(mapperFile, format=mapperFormat)
    mapper.format = IP2ASMapper.PFX2AS_FORMAT

    c = TraceCampaign(campaignFile, format=traceFormat)
    c.nickname = nickname

    c.writeCampaignSummary()
    c.IP2ASMappingAndRelated(mapper)
    nullTracesDict = c.getNullTraces()
    c.filterOutTraces(nullTracesDict["details"]["nullTracesList"])

    # c.writeEgressPointList_MDAFormat()
    #c.writeEgressPointList()
    # c.writeFirstEgressPointListWithNextIps()

    c2 = TraceCampaign(toEgressCampaignFile, format=traceFormat)  # have c1 and c2 ALWAYS the same format?
    c2.IP2ASMappingAndRelated(mapper)

    if toEgressMDACampaignFile:
        c3 = MDATraceCampaign(toEgressMDACampaignFile)
    else:
        c3 = None

    diz = {}
    for level in range(1, 6):
        cwEP = analyzeLevel(c, c2, c3, level)
        if cwEP:
            # res = perASAnalysis(cwEP["notUndersampled"])
            res = perASAnalysis(cwEP["notNoisy"])
            diz[level] = res
        else:
            diz[level] = None
    # pprint (diz)

    c.dumpDestMDAInput()
    c.writePerTraceSummary()

    # c.writePerTraceMetricCorrelationSummary()
    return diz


def analyzeCampaign2(campaignFile, mapperFile,
                     toEgressCampaignFile=None, mdaFolder=None, nickname=None,
                     traceFormat=Trace.SCAMPER_FORMAT):
    """
    """

    if nickname:
        print ":" * 50
        print '{:^50}'.format('CAMPAIGN: %s' % nickname)
        print ":" * 50

    mapper = IP2ASMapper(mapperFile)
    print "IP-to-AS mapping loaded"
    c = TraceCampaign(campaignFile, format=traceFormat)
    c.nickname = nickname
    print "transit traces loaded"

    #c.writeCampaignSummary()
    c.IP2ASMappingAndRelated(mapper)
    print "IP-to-AS mapping done on transit traces"

    nullTracesDict = c.getNullTraces()
    c.filterOutTraces(nullTracesDict["details"]["nullTracesList"])

    if toEgressCampaignFile is None:
        c.writeEgressPointList()
    else:
        c2 = TraceCampaign(toEgressCampaignFile, format=traceFormat)  # have c1 and c2 ALWAYS the same format?
        print "direct traces loaded"
        c2.IP2ASMappingAndRelated(mapper)
        print "IP-to-AS mapping done on direct traces"

    if mdaFolder:
        dstMDA = DestinationMDACampaign(mdaFolder, mapper, c)
        print "destination MDA folder loaded"

    diz = {}
    for level in range(1, 3):
        cwEP = analyzeLevel2(c, c2, dstMDA, level)
        if cwEP:
            # res = perASAnalysis(cwEP["notUndersampled"])
            res = perASAnalysis(cwEP["notNoisy"])
            diz[level] = res
        else:
            diz[level] = None
    # pprint (diz)

    if not mdaFolder:
        c.dumpDestMDAInput()

    c.writePerTraceSummary2()

    #sys.exit()
    # c.writePerTraceMetricCorrelationSummary()
    #return diz


def plotMarginalUtility(dizList, labels):
    from pylab import *
    rcParams['legend.loc'] = 'best'
    COLS = 1
    ROWS = 1
    f, axes = plt.subplots(ROWS, COLS, figsize=(4, 3))
    axes2 = axes.twinx()
    axes.set_prop_cycle(cycler('color', ['r', 'g', 'b', 'y']))
    axes2.set_prop_cycle(cycler('color', ['r', 'g', 'b', 'y']))

    counter = 0
    for diz in dizList:
        label = labels[counter]
        counter += 1
        asnum = 0
        paths = 0

        distanceL = []
        asnumberL = []
        avgPathsL = []

        # USE TEX (occhio alle label!)
        plt.rc('text', usetex=True)
        plt.rc('font', family='serif')
        #        plt.rc('font', size=20)
        sns.set_style({'font.family': 'serif', 'font.serif': 'Computer Modern'})
        sns.set_context("paper", font_scale=1, rc={"lines.linewidth": 3.0})
        sns.set_style("ticks",
                      {
                          "xtick.direction": "in",
                          "ytick.direction": "in",
                          "ytick.major.size": 20,
                          "ytics.minor.size": 5,
                          "xticks.major.size": 20,
                          "xtick.minor.size": 5
                      }
                      )

        #        axes.rc('axes', prop_cycle=(cycler('color', ['r', 'r', 'g', 'g','b', 'b', 'y', 'k', 'm'])))
        #        axes2.rc('axes', prop_cycle=(cycler('color', ['r', 'r', 'g', 'g','b', 'b', 'y', 'k', 'm'])))

        for lvl in diz:
            if diz[lvl] == None:
                asnum += 0
                paths += 0
            else:
                asnum += len(diz[lvl])
                paths += sum([diz[lvl][AS]["paths"] for AS in diz[lvl]])

            avgPaths = float(paths) / asnum

            distanceL.append(lvl)
            asnumberL.append(asnum)
            avgPathsL.append(avgPaths)
            # print "{}\t{}\t{}".format(lvl, asnum, avgPaths)

        axes2.plot(distanceL, avgPathsL, ":")
        axes.plot(distanceL, asnumberL, "-", label=label)
        axes.legend()

        axes.set(xlabel="AS Distance", ylabel="Number of ASes")
        axes2.set(ylabel="Paths per AS (AVG)")
        axes.set_ylim(0, 22)
        axes2.set_ylim(0, 20000)

        axes.set_xticks(distanceL)
        axes.set_yticks(range(0, 23, 2))
        axes2.set_yticks(range(0, 80001, 10000))

        plt.subplots_adjust(right=0.8)
        plt.savefig("utility.pdf", format="pdf")


def analyzeLevel2(c, c2, dstMDA, level):
    """
    :param c: transit traces campaign;
    :param c2: direct traces campaign;
    :param mdaFolder: folder containing results of ECMP campaign;
    :param level: AS distance from the vantage point

    :return:
    """

    cwEP = c.getCWEgressPoints2(c2, dstMDA, level)
    c.write_incfibte_summary(level=level)

    return cwEP

def analyzeLevel(campaignObj, refCampaignObj, mdaCampaignObj, level):
    """
    Generates plots (distribution of M1 and M2 across different CWEgressPoints).
    Generates BIGPICTURE.
    Generates DETAILS.
    """

    c = campaignObj
    c2 = refCampaignObj
    c3 = mdaCampaignObj

    c.getCWEgressPoints(c2, c3, level)
    cwEP = c.writeCWEgressSummary(OutfileName="%s-SUMMARY-L%s.txt" % (c.nickname, level))
    if not cwEP:
        print "%s: no egress found at distance %s" % (c.nickname, level)
        return

    # GRAPHS
    #    c.plotFIBIncScaleM1(cwEP["notUndersampled"], "%s-incscaleM1-L%s.pdf" % (c.nickname, level))
    #    c.plotFIBIncScaleM2(cwEP["notUndersampled"], "%s-incscaleM2-L%s.pdf" % (c.nickname, level))
    #    c.plotFIBIncScaleM3(cwEP["notUndersampled"], "%s-incscaleM3-L%s.pdf" % (c.nickname, level))
    #    c.plotFIBIncScaleM4(cwEP["notUndersampled"], "%s-incscaleM4-L%s.pdf" % (c.nickname, level))

    c.writeCWEgressBigPictureReport(cwEgressList=cwEP["notNoisy"],
                                    outFileName="%s-SELECTED-BIGPICTURE-L%s.csv" % (c.nickname, level))
    c.writeCWEgressDetails(c2, cwEgressList=cwEP["notNoisy"],
                           outFileName="%s-SELECTED-DETAILS-L%s.txt" % (c.nickname, level), tracesToPrint=200)

    return cwEP


def perASAnalysis(cwEPList):
    allcount = defaultdict(int)
    incFIBcount = defaultdict(int)
    incFIBcount2 = defaultdict(int)

    for x in cwEPList:

        if x.classification() in [CWEgressPoint.BGPDETOUR, CWEgressPoint.DIFFERENTINGRESS,
                                  CWEgressPoint.MULTIPLEINGRESSES, CWEgressPoint.SPURIOUS1, CWEgressPoint.SPURIOUS2,
                                  CWEgressPoint.SPURIOUS3, CWEgressPoint.SPURIOUS4]:
            continue

        allcount[x.AS] += x.occ
        incFIBcount[x.AS] += x.FIBInconsistencyMetricABS
        incFIBcount2[x.AS] += x.FIBInconsistencyMetric2ABS

    retDict = {}
    for AS in allcount:
        retDict[AS] = {"M1": incFIBcount[AS],
                       "M2": incFIBcount2[AS],
                       "paths": allcount[AS]
                       }

    return retDict


#####################
#   MAIN PROGRAMS   #
#####################

def testMain(which):
    dizlist = []
    labels = []
    if "STR" in which:
        print ""
        # STRASBOURG
        d = analyzeCampaignXXX("../data/traces/strasbourg/strasbourg-campaign2-20180807.adump",
                               "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                               "../data/traces/strasbourg/strasbourg-campaign2-egress-20180815.adump",
                               "",
                               #"../data/traces/strasbourg/STRASBOURG2-firstegress-mda-tcp-all-20180825.txt",
                               # "/home/valerio/fib-inconsistencies/data/traces/strasbourg/STRASBOURG2-firstegress-mda-udp-all-20180824.txt", #"/home/valerio/fib-inconsistencies/data/traces/strasbourg/STRASBOURG2-firstegress-mda-all-20180822.txt",
                               nickname="STRASBOURG2")
        dizlist.append(d)
        labels.append("Strasbourg")

    if "SEA" in which:
        print ""
        # SEATTLE
        d = analyzeCampaignXXX("../data/traces/seattle/seattle-campaign2-20180807.adump",
                               "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                               "../data/traces/seattle/seattle-campaign2-egress-20180815.adump",
                               "",
                               #"/home/valerio/fib-inconsistencies/data/traces/seattle/SEATTLE2-firstegress-mda-udp-all-20180824.txt",
                               # "/home/valerio/fib-inconsistencies/data/traces/seattle/SEATTLE2-firstegress-mda-all-20180822.txt",
                               nickname="SEATTLE2")
        dizlist.append(d)
        labels.append("Seattle")

    if "NAP" in which:
        print ""
        # NAPOLI
        d = analyzeCampaignXXX("../data/traces/napoli/napoli-campaign2-20180806.adump",
                               "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                               "../data/traces/napoli/napoli-campaign2-egress-20180814.adump",
                               "",
                               #"../data/traces/napoli/NAPOLI2-firstegress-mda-udp-all-20180824.txt",
                               # "../data/traces/napoli/NAPOLI2-firstegress-all.mda-20180820.txt",
                               nickname="NAPOLI2")
        dizlist.append(d)
        labels.append("Napoli")

    if "PAR" in which:
        print ""
        # PARIS
        d = analyzeCampaignXXX("../data/traces/ripe/ripe-paris/137_194_165_21.json",
                               "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                               "../data/traces/ripe/ripe-paris-firstegress/137_194_165_21.json",
                               "",
                               nickname="RIPE-PARIS",
                               traceFormat=Trace.RIPEATLAS_FORMAT)
        dizlist.append(d)
        labels.append("Paris")

    return
    plotMarginalUtility(dizlist, labels)

    as2campaign_lvl = defaultdict(list)
    as2paths = defaultdict(int)
    as2m1 = defaultdict(int)
    as2m2 = defaultdict(int)
    for i in range(0, len(dizlist)):
        print labels[i]
        diz = dizlist[i]
        for lvl in diz:
            if not diz[lvl]:
                continue
            for AS in diz[lvl]:
                as2campaign_lvl[AS].append((i, lvl))

                print "{} {} {}/{} {}/{}".format(lvl, AS, diz[lvl][AS]["M1"], diz[lvl][AS]["paths"], diz[lvl][AS]["M2"],
                                                 diz[lvl][AS]["paths"])

    # printing per-AS info - should be put in a separate function
    for AS in as2campaign_lvl:
        for x in as2campaign_lvl[AS]:
            campi = x[0]
            lvli = x[1]
            as2paths[AS] += dizlist[campi][lvli][AS]["paths"]
            as2m1[AS] += dizlist[campi][lvli][AS]["M1"]
            as2m2[AS] += dizlist[campi][lvli][AS]["M2"]

    perc = {}
    perc2 = {}
    for AS in as2paths:
        perc[AS] = float(as2m1[AS]) / as2paths[AS]
        perc2[AS] = float(as2m2[AS]) / as2paths[AS]

    whois = WhoisServer("riswhois.ripe.net").asLookup

    for AS in sorted(as2paths, key=lambda x: as2m1[x], reverse=True):
        asinfo = "{}|{}".format(AS, whois(AS))
        s1 = "{:d}/{:d} ({:.2f})".format(as2m1[AS], as2paths[AS], perc[AS])
        s2 = "{:d}/{:d} ({:.2f})".format(as2m2[AS], as2paths[AS], perc2[AS])
        print "{} {} {}".format(asinfo, s1, s2)


def main1():
    # NAPOLI
    analyzeCampaignXXX("../data/traces/napoli/napoli-campaign1-20180726.adump",
                       "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                       "../data/traces/napoli/napoli-campaign1-egress-new.adump", nickname="NAPOLI")

    print ""
    # STRASBOURG
    analyzeCampaignXXX("../data/traces/strasbourg/strasbourg-campaign1-20180724.adump",
                       "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                       "../data/traces/strasbourg/strasbourg-campaign1-egress-20180725.adump",
                       "/home/valerio/fib-inconsistencies/data/traces/strasbourg/STRASBOURG2-firstegress.mda-20180820.txt",
                       nickname="STRASBOURG")

    print ""
    # SEATTLE
    analyzeCampaignXXX("../data/traces/seattle/seattle-campaign1-20180726.adump",
                       "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                       "../data/traces/seattle/seattle-campaign1-egress-20180730.adump", nickname="SEATTLE")


def cristel_main():
    """
    """
    mapperFile = "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as"
    mapper = IP2ASMapper(mapperFile)
    c = TraceCampaign("../data/traces/additional-traces-for-cristel/cristel.adump")
    c.nickname = "CRISTEL"
    c.IP2ASMappingAndRelated(mapper)
    c.writeEgressPointList()

    c2 = TraceCampaign("../data/traces/additional-traces-for-cristel/cristel-firstegress.adump")
    c2.IP2ASMappingAndRelated(mapper)

    print "TRANSIT"
    for t in c.traces:
        print t

    print "DIRECT"
    for t in c2.traces:
        print t


def print_egress_points_main():
    """
    Generates egress point ip list.
    """
    usage = "usage: %s <traces.adump>" % sys.argv[0]

    if len(sys.argv) < 2:
        print("ERROR: Bad Arguments")
        print(usage)
        sys.exit(1)

    filename = sys.argv[1]
    basename = filename.split(".adump")[0]
    outfilename = "%s-egress.ips" % basename

    print("Creating Mapper")
    mapperFile = "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as"
    mapper = IP2ASMapper(mapperFile)

    c = TraceCampaign(filename)
    #c.nickname = basename
    c.IP2ASMappingAndRelated(mapper)
    print("\t\tCreating list")
    c.writeEgressPointList(outFileName=outfilename)
    print("%s created" % outfilename)


def julian_main():
    """
    """
    usage = "usage: %s <DATE> ... where DATE=YEARMONTHDAY. Example: 20191231" % sys.argv[0]

    if len(sys.argv)!=2:
        print("ERROR: Bad Arguments")
        print(usage)
        sys.exit(1)

    DATE = sys.argv[1]
    PEERs = ["uw", "isi", "grnet", "neu", "clemson", "utah"]
    DUMP_FILE = "%s.%s.adump"
    NICKNAME  = "%s.%s"

    print("Creating Mapper")
    mapperFile = "/home/julian/Desktop/inc-FIB-resources/routeviews-rv2-20190421-1200.pfx2as"
    mapper = IP2ASMapper(mapperFile)

    print("Analyzing Data")
    for peer in PEERs:
        dump_file = DUMP_FILE % (peer, DATE)
        nickname  = NICKNAME  % (peer, DATE)

        print("\t%s" % dump_file)
        if not os.path.isfile(dump_file):
            print("\t\tERROR: file is missing" % dump_file)
            continue

        c = TraceCampaign(dump_file)
        c.nickname = nickname
        print("\t\tIP2AS mapping")
        c.IP2ASMappingAndRelated(mapper)
        print("\t\tCreating list")
        c.writeEgressPointList()
    print("Finished")


def test_new_stuff():
    """
    integrates Destination MDA
    """

    # analyzeCampaign2("../data/traces/napoli/napoli-campaign2-20180806.adump",
    #                  "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
    #                  toEgressCampaignFile="../data/traces/napoli/napoli-campaign2-egress-20180814.adump",
    #                  mdaFolder="../data/traces/napoli/napoli-dst-mda-adjusted", nickname="NAPOLI-NEW",
    #                  traceFormat=Trace.SCAMPER_FORMAT)


    # analyzeCampaign2("../data/traces/seattle/seattle-campaign2-20180807.adump",
    #                        "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
    #                        toEgressCampaignFile="../data/traces/seattle/seattle-campaign2-egress-20180815.adump",
    #                        mdaFolder="../data/traces/seattle/seattle-dst-mda-adjusted",
    #                        nickname="SEATTLE-NEW")


    analyzeCampaign2("../data/traces/strasbourg/strasbourg-campaign2-20180807.adump",
                    "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                    toEgressCampaignFile="../data/traces/strasbourg/strasbourg-campaign2-egress-20180815.adump",
                    mdaFolder="../data/traces/strasbourg/strasbourg-dst-mda-adjusted",
                    nickname="STRASBOURG-NEW",
                    traceFormat=Trace.SCAMPER_FORMAT)


def main2():
    # NAPOLI
    analyzeCampaignXXX("../data/traces/napoli/napoli-campaign2-20180806.adump",
                       "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                       "../data/traces/napoli/napoli-campaign2-egress-20180814.adump", nickname="NAPOLI2")

    print ""
    # STRASBOURG
    analyzeCampaignXXX("../data/traces/strasbourg/strasbourg-campaign2-20180807.adump",
                       "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                       "../data/traces/strasbourg/strasbourg-campaign2-egress-20180815.adump", nickname="STRASBOURG2")

    print ""
    # SEATTLE
    analyzeCampaignXXX("../data/traces/seattle/seattle-campaign2-20180807.adump",
                       "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                       "../data/traces/seattle/seattle-campaign2-egress-20180815.adump", nickname="SEATTLE2")


def main_peering():


    vantagePoints = ["grnet01",
                    "isi01",
                    "strasbg01",
                    "ucl01",
                    "uw01"
                   ]
   
    for vp in vantagePoints:
        

        print "peering-stuff/data/%s/*.adump" % vp
        # assuming that only 2 adump-files are in peering-stuff/data/<vp>/ (transit and egress)
        transit_campaign = filter(lambda x: "egress" not in x, glob.glob("peering-stuff/data/%s/*.adump" % vp))[0]
        internal_campaign = filter(lambda x: "egress" in x, glob.glob("peering-stuff/data/%s/*.adump" % vp))[0]
    
        print "transit campaign: %s" % transit_campaign
        print "internal campaign: %s" % internal_campaign

        analyzeCampaignXXX( transit_campaign,
                            "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                            internal_campaign,
                            nickname=vp
                          )

def main_nlnogring(vplistFile, traceFolder, egressFolder, mapperFile):
    try:
        with open(vplistFile) as vplistf:
            vantagePoints = vplistf.readlines()
            vantagePoints = [x.strip() for x in vantagePoints if not x.startswith("#")]
    except:
        pass

    for vp in vantagePoints:
        
        # assuming that only 2 adump-files are in nlnog-ring-stuff/data/<vp>/ (transit and egress)
        transit_campaign = filter(lambda x: "egress" not in x, glob.glob("%s/%s*.adump" % (traceFolder, vp)))[0]
        internal_campaign = filter(lambda x: "egress" in x, glob.glob("%s/%s*.adump" % (egressFolder, vp)))[0]  #iucc01.ring.nlnog.net-egress-20191120.warts
    
        print "transit campaign: %s" % transit_campaign
        print "internal campaign: %s" % internal_campaign

        # analyzeCampaignXXX( transit_campaign,
        #                     "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
        #                     internal_campaign,
        #                     nickname=vp.split(".")[0],
        #                     mapperFormat=IP2ASMapper.PFX2AS_FORMAT
        #                   )

        analyzeCampaignXXX( transit_campaign,
                            mapperFile,
                            internal_campaign,
                            nickname=vp.split(".")[0],
                            mapperFormat=IP2ASMapper.BDRMAPIT_FORMAT
                          )


def extract_egresses_main(vplistFile, traceFolder, mapperFile, traceFormat=Trace.SCAMPER_FORMAT, mapperFormat=IP2ASMapper.BDRMAPIT_FORMAT, outFolder="."):

    print "{:^30}\n{:^30}\n{:^30}".format("#"*30, "CURRENT SETUP", "#"*30)


    try:
        with open(vplistFile) as vplistf:
            vantagePoints = vplistf.readlines()
            vantagePoints = [x.strip() for x in vantagePoints if not x.startswith("#")]
    except:
        pass

    traceFolder = traceFolder.rstrip("/")
    outFolder = outFolder.rstrip("/")

    print "VP LIST (%s VPs): %s" %(len(vantagePoints), vplistFile)
    print "RESULTS FOLDER:", traceFolder
    print "MAPPER FILE", mapperFile
    print "OUTFOLDER: ", outFolder
    goon = raw_input("\nIf this setup is not correct change the params! \nContinue? [Y/N] ")
    if goon == "N":
        print "bye!"
        sys.exit()


    mapper = IP2ASMapper(mapperFile, format=mapperFormat)
    mapper.format = IP2ASMapper.PFX2AS_FORMAT
    # pprint(len(mapper.mapInfoBase.keys()))

    for vp in vantagePoints:
        # assuming that only 2 adump-files are in nlnog-ring-stuff/data/<vp>/ (transit and egress AT MOST)
        print "%s/%s*.adump" % (traceFolder, vp)
        print glob.glob("%s/%s*.adump" % (traceFolder, vp))
        #raw_input()
        transit_campaign = filter(lambda x: "egress" not in x, glob.glob("%s/%s*.adump" % (traceFolder, vp)))[0]
        # internal_campaign = filter(lambda x: "egress" in x, glob.glob("nlnog-ring-stuff/data/%s/*.adump" % vp))[0]

        nickname = vp.split(".")[0]
        c = TraceCampaign(transit_campaign, format=traceFormat)
        c.nickname = nickname
        c.IP2ASMappingAndRelated(mapper)
        nullTracesDict = c.getNullTraces()
        c.filterOutTraces(nullTracesDict["details"]["nullTracesList"])

        c.writeEgressPointList(outFileName="%s/%s" % (outFolder, c.nickname+"-egress.ips"))
        c.writeStatistics(outFileName="%s/%s" % (outFolder, c.nickname+"-stats.log"))


def extract_MDA_list_main(vplistFile, traceFolder, DIRsFolder, mapperFile, traceFormat=Trace.SCAMPER_FORMAT, mapperFormat=IP2ASMapper.BDRMAPIT_FORMAT, outFolder="."):

    print "{:^30}\n{:^30}\n{:^30}".format("#"*30, "CURRENT SETUP", "#"*30)


    try:
        with open(vplistFile) as vplistf:
            vantagePoints = vplistf.readlines()
            vantagePoints = [x.strip() for x in vantagePoints if not x.startswith("#")][:1]
    except:
        print 'Error reading the VP list...'
        sys.exit()

    traceFolder = traceFolder.rstrip("/")
    DIRsFolder = DIRsFolder.rstrip("/")
    outFolder = outFolder.rstrip("/")

    print "VP LIST (%s VPs): %s" %(len(vantagePoints), vplistFile)
    print "RESULTS FOLDER:", traceFolder
    print "MAPPER FILE", mapperFile
    print "OUTFOLDER: ", outFolder
    goon = raw_input("\nIf this setup is not correct change the params! \nContinue? [Y/N] ")
    if goon == "N":
        print "bye!"
        sys.exit()

    print "Creating Mapper..."
    mapper = IP2ASMapper(mapperFile, format=mapperFormat)
    mapper.format = IP2ASMapper.PFX2AS_FORMAT
    # pprint(len(mapper.mapInfoBase.keys()))

    
    for vp in vantagePoints:
        nickname = vp.split(".")[0]
        TIRs_campaign = filter(lambda x: "egress" not in x, glob.glob("%s/%s*.adump" % (traceFolder, vp)))[0]
        DIRs_campaign = filter(lambda x: "egress" in x, glob.glob("%s/%s*.adump" % (DIRsFolder, vp)))[0]

        print "Analyzing {}...".format(vp)

        print "Reading {}...".format(TIRs_campaign)
        c = TraceCampaign(TIRs_campaign, format=traceFormat)
        c.nickname = nickname
        
        print "Mapping traces to AS and filtering..."
        c.IP2ASMappingAndRelated(mapper)
        nullTracesDict = c.getNullTraces()
        c.filterOutTraces(nullTracesDict["details"]["nullTracesList"])
        
        print 'Getting TIRs...'
        vp_data = c.getTIRs()



        print "Reading {}...".format(DIRs_campaign)
        c = TraceCampaign(DIRs_campaign, format=traceFormat)
        c.nickname = nickname
            
        print "Mapping traces to AS and filtering..."
        c.IP2ASMappingAndRelated(mapper)
        nullTracesDict = c.getNullTraces()
        c.filterOutTraces(nullTracesDict["details"]["nullTracesList"])
        
        # q_tot_pref = []
        # for AS in vp_data:
        #     for i_e in vp_data[AS]:
        #         q_tot_pref.append(len(vp_data[AS][i_e][TIR_LABEL]))
        # q_tot_pref = ','.join(list(map(lambda x: str(x), q_tot_pref)))
        # f = open("%s/%s" % (outFolder, c.nickname+"-qprefixes.log"), 'w')
        # f.write("{}\n".format(q_tot_pref))
        # f.close()                 
        # continue

        print 'Getting DIRs...'
        vp_data = c.getDIRs(vp_data = vp_data,
                            outFileName="%s/%s" % (outFolder, c.nickname+"-stats.log"))

        print 'Dumping data...'

        # for AS in vp_data:                    
        #     qTIRsAS = sum([len(vp_data[AS][i_e][TIR_LABEL]) for i_e in vp_data[AS] if DIR_LABEL in vp_data[AS][i_e] and TIR_LABEL in vp_data[AS][i_e]])
        #     qTIRsVP += qTIRsAS
        #     print AS, qTIRsAS
        # print 'VP --> {}'.format(qTIRsVP) 
        
        qTIRs = defaultdict(dict)
        q_tirs_couple = []

        q_noDIR = 0
        q_noTIR = 0
        q_noMinTirs = 0
        q_DuplicatedDIR = 0
        q_CorrectDIR = 0
        q_DIRsWithWildcards = 0        
        with open("%s/%s" % (outFolder, c.nickname+"-pre-processing-input.ips"), 'w') as f:
            for AS in vp_data:
                for i_e in vp_data[AS]:
                    if DIR_LABEL not in vp_data[AS][i_e]:
                        q_noDIR += 1
                        continue
                    if TIR_LABEL not in vp_data[AS][i_e]:
                        q_noTIR += 1
                        continue
                    qTIRs_ie = len(vp_data[AS][i_e][TIR_LABEL])
                    q_tirs_couple.append(str(qTIRs_ie))
                    if qTIRs_ie < Q_TIRS_MIN_IE:
                        q_noMinTirs += 1
                        continue
                    qTIRs[AS][i_e] = qTIRs_ie
                    q_CorrectDIR += 1                    
                    if len(vp_data[AS][i_e][DIR_LABEL]) > 1:
                        q_DuplicatedDIR += 1
                    if 'q' in vp_data[AS][i_e][DIR_LABEL][0]:
                        q_DIRsWithWildcards += 1

                    # vp_data[AS][i_e][DIR_LABEL] = vp_data[AS][i_e][DIR_LABEL][0]
                    # DIR_str = ','.join(vp_data[AS][i_e][DIR_LABEL])
                    # for TIR_data in vp_data[AS][i_e][TIR_LABEL]:
                    #     dst_TIR = TIR_data[0]
                    #     TIR_str  = ','.join(TIR_data[1])
                    #     # AS, IN, OUT, DST, same, sub_t, sub_d
                    #     outline = ';'.join([AS, i_e[0], i_e[1], dst_TIR, '?', TIR_str, DIR_str])
                    #     f.write('{}\n'.format(outline))
        str_tirs_per_couple = ','.join(q_tirs_couple)

        with open("%s/%s" % (outFolder, c.nickname+"-wildcards.log"), 'w') as f:
            f.write('{};{}\n'.format(q_DIRsWithWildcards, q_CorrectDIR))

        # f = open("%s/%s" % (outFolder, c.nickname+"-stats.log"), 'a')
        # f.write("{noDIR};{noTIR};{noMIN};{OK};{TOT};{qTIRs_vs_Couple}\n".format(
        #             noDIR = q_noDIR,
        #             noTIR = q_noTIR,
        #             noMIN = q_noMinTirs,
        #             OK = q_CorrectDIR,
        #             TOT = sum([len(vp_data[AS]) for AS in vp_data]),
        #             qTIRs_vs_Couple = str_tirs_per_couple
        #             ))
        # f.close()
        #     # for AS in vp_data:
        #     #     for i_e in vp_data[AS]:
        #     #         if DIR_LABEL in vp_data[AS][i_e] and TIR_LABEL in vp_data[AS][i_e]:
        #     #             qTIRs_ie = len(vp_data[AS][i_e][TIR_LABEL])
        #     #             if qTIRs_ie > Q_TIRS_MIN_IE:
        #     #                 qTIRs[AS][i_e] = qTIRs_ie
        #     #                 if len(vp_data[AS][i_e][DIR_LABEL]) > 1:
        #     #                     wtf += 1
        #     #                 vp_data[AS][i_e][DIR_LABEL] = vp_data[AS][i_e][DIR_LABEL][0]
        #     #                 DIR_str = ','.join(vp_data[AS][i_e][DIR_LABEL])
        #     #                 for TIR_data in vp_data[AS][i_e][TIR_LABEL]:
        #     #                     dst_TIR = TIR_data[0]
        #     #                     TIR_str  = ','.join(TIR_data[1])
        #     #                     # AS, IN, OUT, DST, same, sub_t, sub_d
        #     #                     outline = ';'.join([AS, i_e[0], i_e[1], dst_TIR, '?', TIR_str, DIR_str])
        #     #                     f.write('{}\n'.format(outline))
        # qTIRsVP = 0                                
        # for AS in qTIRs:
        #     qTIRsVP += sum(qTIRs[AS].values())
        #     print AS
        #     pprint(qTIRs[AS])
        # print 'VP --> {}'.format(qTIRsVP)
        # print 'wtf = {}'.format(q_DuplicatedDIR)
        # # with open("%s/%s" % (outFolder, c.nickname+"-pre-processing-input.ips"), 'w') as f:
        # #     for AS in vp_data:
        # #         for i_e in vp_data[AS]:
        # #             for IR_data in vp_data[AS][i_e][TIR_LABEL]:
        # #                 prfx   = IR_data[0]
        # #                 IR_str = ','.join(IR_data[1])
        # #                 outline = ';'.join([AS, i_e[0], i_e[1], prfx, IR_str, IR_str])
        # #                 f.write('{}\n'.format(outline))
        # # print('Done')

def test_new_mapper():
    """

    :return:
    """

    # nodes.list
    vantagePoints = [
        "comcast01.ring.nlnog.net",
        "belwue01.ring.nlnog.net",
        "mtwentyfourseven03.ring.nlnog.net",
        "comvive01.ring.nlnog.net",
        "linode01.ring.nlnog.net",
        "ntt02.ring.nlnog.net",
        "melbourne01.ring.nlnog.net",
        "iij01.ring.nlnog.net",
        "dna01.ring.nlnog.net",
        "ehsab02.ring.nlnog.net",
        "nforce01.ring.nlnog.net",
        "tnnet01.ring.nlnog.net",
        "qcom01.ring.nlnog.net",
        "plurimedia01.ring.nlnog.net",
        "a101.ring.nlnog.net",
        "iplan01.ring.nlnog.net",
        "kordia01.ring.nlnog.net",
        "cloudscale01.ring.nlnog.net",
        "iucc01.ring.nlnog.net",
        "serversaustralia01.ring.nlnog.net",
        "grnet01.ring.nlnog.net",
        "nicbr01.ring.nlnog.net",
        "poprs01.ring.nlnog.net",
        "vpsfree01.ring.nlnog.net",
        "trueinternet01.ring.nlnog.net"
    ]




    # information at ingress and egress granularity
    in_pfx2as = set()
    in_bdrmapit = set()
    ex_pfx2as = set()
    ex_bdrmapit = set()

    # information at trace granularity
    changed_counter = 0  # counts how many traces returns different AS sequences on the path
    alltraces = 0

    for vp in vantagePoints:
        # assuming that only 2 adump-files are in nlnog-ring-stuff/data/<vp>/ (transit and egress)
        print "nlnog-ring-stuff/data/%s/*.adump" % vp
        transit_campaign = filter(lambda x: "egress" not in x, glob.glob("nlnog-ring-stuff/data/%s/*.adump" % vp))[0]
        internal_campaign = filter(lambda x: "egress" in x, glob.glob("nlnog-ring-stuff/data/%s/*.adump" % vp))[0]

        mapperFile_bdrmapit = "../data/ip2as/bdrmapip-output-allnlnogtraces-20191005.sqlite3"
        mapperFile_pfx2as = "../data/ip2as/routeviews-rv2-20190505-1200.pfx2as"

        print "transit campaign: %s" % transit_campaign
        print "internal campaign: %s" % internal_campaign

        mapper_bdrmapit = IP2ASMapper(mapperFile_bdrmapit, format=IP2ASMapper.BDRMAPIT_FORMAT)
        mapper_pfx2as = IP2ASMapper(mapperFile_pfx2as, format=IP2ASMapper.PFX2AS_FORMAT)
        c1 = TraceCampaign(transit_campaign, format=Trace.SCAMPER_FORMAT)
        c2 = TraceCampaign(transit_campaign, format=Trace.SCAMPER_FORMAT)
        c1.IP2ASMappingAndRelated(mapper_bdrmapit)
        c2.IP2ASMappingAndRelated(mapper_pfx2as)


        for ip in c1.tracesByDestination:
            t1 = c1.tracesByDestination[ip]
            t2 = c2.tracesByDestination[ip]

            # INGRESS POINTS PER AS
            for i in t1.ingressPoints:
                inip = i.ipAddress
                inas = i.AS
                in_bdrmapit.add((inas, inip))

            for i in t2.ingressPoints:
                inip = i.ipAddress
                inas = i.AS
                in_pfx2as.add((inas, inip))

            # EGRESS POINTS PER AS
            for e in t1.egressPoints:
                exip = e.ipAddress
                exas = e.AS
                ex_bdrmapit.add((exas, exip))

            for e in t2.ingressPoints:
                exip = e.ipAddress
                exas = e.AS
                ex_pfx2as.add((exas, exip))

            alltraces += 1
            if t1.ASHops != t2.ASHops:
                changed_counter += 1

    in_bdrmapit_only = in_bdrmapit - in_pfx2as
    in_pfx2as_only = in_pfx2as - in_bdrmapit
    in_both = in_pfx2as & in_bdrmapit

    ex_bdrmapit_only = ex_bdrmapit - ex_pfx2as
    ex_pfx2as_only = ex_pfx2as - ex_bdrmapit
    ex_both = ex_pfx2as & ex_bdrmapit


    print "INGRESS POINTS"
    print "{}\t{}\t{}".format("PFX2AS-ONLY", "BOTH", "BDRMAPIT-ONLY")
    print "{}\t{}\t{}".format(len(in_pfx2as_only), len(in_both), len(in_bdrmapit_only))

    print "{}\t{}\t{}".format("FALSE/PFX2AS", "TRUE/PFX2AS",  "SEEN/BDRMAP")
    print "{:.2f}%\t{:.2f}%\t{:.2f}%".format(
                                            float(len(in_pfx2as_only))*100 / (len(in_pfx2as_only)+len(in_both)),
                                            float(len(in_both))*100 / (len(in_pfx2as_only) + len(in_both)),
                                            float(len(in_both))*100 / (len(in_bdrmapit_only) + len(in_both))
                                            )



    print "EGRESS POINTS"
    print "{}\t{}\t{}".format("PFX2AS-ONLY", "BOTH", "BDRMAPIT-ONLY")
    print "{}\t{}\t{}".format(len(ex_pfx2as_only), len(ex_both), len(ex_bdrmapit_only))

    print "{}\t{}\t{}".format("FALSE/PFX2AS", "TRUE/PFX2AS",  "SEEN/BDRMAP")
    print "{:.2f}%\t{:.2f}%\t{:.2f}%".format(
                                            float(len(ex_pfx2as_only))*100 / (len(ex_pfx2as_only)+len(ex_both)),
                                            float(len(ex_both))*100 / (len(ex_pfx2as_only) + len(ex_both)),
                                            float(len(ex_both))*100 / (len(ex_bdrmapit_only) + len(ex_both))
                                            )

    print changed_counter
    print alltraces


def main3():
    # mdaC = MDATraceCampaign("/home/valerio/fib-inconsistencies/data/traces/seattle/test.txt")
    mdaC = MDATraceCampaign("/home/valerio/fib-inconsistencies/data/traces/seattle/test2.txt")
    for mdat in mdaC.traces:
        print mdat.G.edges()
        print mdat.getSimplePaths("C", "Z")


def testParser():
    # c = TraceCampaign("/home/valerio/fib-inconsistencies/data/traces/ripe/ripe-paris/137_194_165_21.json", format=Trace.RIPEATLAS_FORMAT)

    c = TraceCampaign("../data/traces/strasbourg/strasbourg-campaign2-20180807.adump")

    mapper = IP2ASMapper("../data/ip2as/routeviews-rv2-20180722-1200.pfx2as")
    c.IP2ASMappingAndRelated(mapper)
    for t in c.traces:
        # t = Trace(x, format=Trace.RIPEATLAS_FORMAT)
        # print t
        # print t.destRTT

        #        pprint (t.hops)
        #        pprint (t.rtts)

        ips = flatten(t.hops.values())
        for ip in ips:
            if ip != 'q':
                print ip, t.rttsByIP[ip], np.average(t.rttsByIP[ip])

def testDestMDA():

    mapper = IP2ASMapper("../data/ip2as/routeviews-rv2-20180722-1200.pfx2as")
    folder = sys.argv[1]
    directFile = "../data/traces/napoli/napoli-campaign2-20180806.adump"
    c = TraceCampaign(directFile)
    c.IP2ASMappingAndRelated(mapper)
    d = DestinationMDACampaign(folder, mapper, c)



    ip1 = "1.220.81.46"
    as1 = "174"

    ip2 = "62.220.12.201"
    as2 = "1299"

    sub_t1 = c.tracesByDestination[ip1].ASInfo[as1].subpath
    sub_t2 = c.tracesByDestination[ip2].ASInfo[as2].subpath

    sub_d1 = ('149.6.22.73',
      '154.54.57.66',
      '130.117.2.21',
      '130.117.50.165',
      '154.54.57.69',
      '154.54.1.178',
      '154.54.0.221',
      '154.54.29.173',
      '154.54.7.129',
      '154.54.44.169',
      '154.54.31.89',
      '154.54.42.97',
      '154.54.44.137',
      '154.54.43.10')

    sub_d2 = ('80.239.135.52', '62.115.142.140', '62.115.116.164', '213.155.129.189')

    print d.returnECMPOutcome(sub_t1, sub_d1, ip1, as1)
    print d.returnECMPOutcome(sub_t2, sub_d2, ip2, as2)

    print d.returnECMPOutcome(sub_t2, sub_d2, "1.2.3.4", as2)

    print d.returnECMPOutcome(sub_t2, sub_t2, ip2, as2)

    print d.returnECMPOutcome(sub_t2, ("a", "b", "c"), ip2, as2)


def TE_main():

    vantagePoints = [
            "iplan01.ring.nlnog.net",
            "linode01.ring.nlnog.net",
            "nforce01.ring.nlnog.net",
            "trueinternet01.ring.nlnog.net",
            "comvive01.ring.nlnog.net",
            "iij01.ring.nlnog.net",
            "kordia01.ring.nlnog.net",
            "mtwentyfourseven03.ring.nlnog.net",
            "serversaustralia01.ring.nlnog.net",
            "vpsfree01.ring.nlnog.net"
            ]

  
    for vp in vantagePoints:
        # assuming that only 2 adump-files are in nlnog-ring-stuff/data/<vp>/ (transit and egress)
        print "nlnog-ring-stuff/data/%s/*.adump" % vp

        TIR = filter(lambda x: "egress" not in x, glob.glob("nlnog-ring-stuff/data/%s/*.adump" % vp))[0]
        DIR= filter(lambda x: "egress" in x, glob.glob("nlnog-ring-stuff/data/%s/*.adump" % vp))[0]
        mdaFolder = "validation-data-raw/%s" % vp


        print "transit campaign: %s" % TIR
        print "internal campaign: %s" % DIR
        print "MDA folder: %s" % mdaFolder

        analyzeCampaign2(TIR,
                         "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                         toEgressCampaignFile=DIR,
                         mdaFolder=mdaFolder,
                         nickname=vp,
                         traceFormat=Trace.SCAMPER_FORMAT)



def main_skip1sthop():
    # nodes.list
    vantagePoints = [
        "comcast01.ring.nlnog.net",
        #"belwue01.ring.nlnog.net",
        #"mtwentyfourseven03.ring.nlnog.net",
        #"comvive01.ring.nlnog.net"
    ]

    for vp in vantagePoints:
        # assuming that only 2 adump-files are in nlnog-ring-stuff/data/<vp>/ (transit and egress)
        print "nlnog-ring-stuff/data/%s/*.adump" % vp
        transit_campaign = filter(lambda x: "egress" not in x, glob.glob("nlnog-ring-stuff/data/%s/*.adump" % vp))[
            0]
        internal_campaign = filter(lambda x: "egress" in x, glob.glob("nlnog-ring-stuff/data/%s/*.adump" % vp))[0]

        print "transit campaign: %s" % transit_campaign
        print "internal campaign: %s" % internal_campaign

        analyzeCampaignXXX(transit_campaign,
                           "../data/ip2as/routeviews-rv2-20180722-1200.pfx2as",
                           internal_campaign,
                           nickname=vp.split(".")[0]
                           )


def loop_in_path(path):
    for i in range(len(path) - 1):
        if path[i] not in ['q', None, 'Private']:
            for j in range(i + 1, len(path)):
                if path[j] == path[i]:
                    return True
    return False 

if __name__ == "__main__":
    #testDestMDA()
    # cristel_main()
    # sys.exit()
    # testParser()
    # testMain(["PAR"])
    #testMain(["STR"])
    #testMain(["SEA"])
    #testMain(["NAP"])
    #testMain(["NAP", "SEA", "STR"])
    # main2()
    # main3()
    # test_new_stuff()
    #julian_main()


    # Measurements Paper
    # extract_egresses_main("nlnog-ring-stuff/LARGE-SCALE-2020/nlnog-systematic-selection-20191219.nodes",
    #                       "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/TIRs-campaign-results",
    #                       "/home/julian/bdrmapit_trying/bdrmapit.output",
    #                       outFolder="nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/MDA-IP-lists")

    # Statistics for paper
    # extract_egresses_main("nlnog-ring-stuff/LARGE-SCALE-2020/nlnog-systematic-selection-20191219.nodes",
    #                       "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/TIRs-campaign-results",
    #                       "/home/julian/bdrmapit_trying/bdrmapit.output",
    #                       outFolder="nlnog-ring-stuff/LARGE-SCALE-2020/backup_results/stats_tirs_camp")

    # Experiment Strasbourg
    # extract_egresses_main("nlnog-ring-stuff/LARGE-SCALE-2020/testing_node.list",
    #                       "nlnog-ring-stuff/LARGE-SCALE-2020/resultsStrasbourg",
    #                       "/home/julian/bdrmapit_trying/stras.output",
    #                       outFolder="nlnog-ring-stuff/LARGE-SCALE-2020/resultsStrasbourg")


    # Measurement Paper
    # extract_MDA_list_main("nlnog-ring-stuff/LARGE-SCALE-2020/nlnog-systematic-selection-20191219.nodes",
    #                       "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/TIRs-campaign-results",
    #                       "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/DIRs-campaign-results",
    #                       "/home/julian/bdrmapit_trying/bdrmapit.output",
    #                       outFolder="nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/pre_processing_input")

    # Statistics for paper
    extract_MDA_list_main("nlnog-ring-stuff/LARGE-SCALE-2020/nlnog-systematic-selection-20191219.nodes",
                          "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/TIRs-campaign-results",
                          "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/DIRs-campaign-results",
                          "/home/julian/bdrmapit_trying/bdrmapit.output",
                          outFolder="nlnog-ring-stuff/LARGE-SCALE-2020/backup_results/stats_dirs_tirs_camp")





    # Experiment Strasbourg
    # extract_MDA_list_main("nlnog-ring-stuff/LARGE-SCALE-2020/testing_node.list",
    #                       "nlnog-ring-stuff/LARGE-SCALE-2020/resultsStrasbourg",
    #                       "nlnog-ring-stuff/LARGE-SCALE-2020/resultsStrasbourg",
    #                       "/home/julian/bdrmapit_trying/stras.output",
    #                       outFolder="nlnog-ring-stuff/LARGE-SCALE-2020/resultsStrasbourg")

    # '''

    # main_nlnogring(vplistFile   = "nlnog-ring-stuff/LARGE-SCALE-2020/nlnog-systematic-selection-20191219.nodes",
    #                traceFolder  = "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/TIRs-campaign-results",
    #                egressFolder = "nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/DIRs-campaign-results",
    #                mapperFile   = "/home/julian/bdrmapit_trying/bdrmapit.output")

    #main_peering()
    #TE_main()
    #main_skip1sthop()
    #test_new_mapper()
    
