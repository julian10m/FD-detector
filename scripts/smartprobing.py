import warnings
warnings.filterwarnings('ignore', r'numpy.dtype')
import random
import sys
import networkx as nx
import utils
import perdest_MDA as mda
from collections import defaultdict
from pprint import pprint
import json

class DataStruct:
    """
    Data structure for each (AS, i, e).
    Records all the prefixes and the related routes
    dictionary: set of routes --> set of prefixes
    keys must be frozenset
    """
    data = None

    def __init__(self):
        self.data = defaultdict(set)

    def __repr__(self, more_verbose = False):
        len_sets_routes = [len(k) for k in self.data.keys()]
        len_sets_prefixes = [len(k) for k in self.data.values()]
        return "%s --> %s, %s" % (str(len_sets_routes), str(len_sets_prefixes), sum(len_sets_prefixes))

    def num_2Ps(self):
        return len(self.data.keys())

    def add(self, prefixes, routes):
        """
        input: set of routes discovered for given prefix(es).
        takes sets for both input parameters, as:
        1) initial campaign produces set of prefixes for each route;
        2) MDA returns set of routes for a given prefix.
        Aggregation is performed based on routes.
        """
        
        intersecting_keys = [k for k in self.data.keys() if len(k.intersection(routes))>0]

        # generate new key (route set)
        new_key = set()
        for k in intersecting_keys:
            new_key = new_key.union(k)
        new_key = new_key.union(routes)
        
        # generate new value (prefix set)
        new_value = set()
        for k in intersecting_keys:
            new_value = new_value.union(self.data[k])
        new_value = new_value.union(prefixes)

        # remove intersecting keys (route set)
        for k in intersecting_keys:
            del self.data[k]

        # add new k:v
        new_key = frozenset(new_key)
        self.data[new_key] = new_value
            



def init(filename):
    """
    Initializes the main data structure based on the input file (list of (tir, dir) couples.
    """
    # MAIN DATA STRUCTURE(S):
    # (AS, iN, out) --> DataStruct
    overall = dict()
    route2prefixes = defaultdict(set)  # maps routes to destinations (prefixes)
    asie2dir = defaultdict(set)  # maps (as, i, e) to dir(s). A unique is expected for each (as, i, e)

    # TMP DATA STRUCTURE(S)
    tmp = dict()

    # import input file
    for x in mda.loadInput(filename):
        AS = x["as"]
        iN = x["in"]
        out = x["out"]
        dst = x["dst"]
        diR = x["sub_d"]
        tir = x["sub_t"]

        tmp[(AS, iN, out, dst)] = tir
        asie2dir[(AS, iN, out)].add(diR)
        route2prefixes[tir].add(dst)
    
    # unique (as, i, e) list
    asie_list = list(set((k[0:3]) for k in tmp))

    # group by AS, i, e
    for AS, iN, out in asie_list:
        
        # empty struct for the new (AS, i, e)
        overall[(AS, iN, out)] = DataStruct()

        # list of routes associated with the specific (AS, iN, out)
        tir_list = set([tmp[k] for k in tmp.keys() if k[0:3]==(AS, iN, out)])

        # map each tir associated with the specific (AS, iN, out) to the related prefixes
        for tir in tir_list:
            
           overall[(AS, iN, out)].add(set(route2prefixes[tir]), {tir})

    return overall, asie2dir


def are_equivalent(r1, r2, wildcard = 'q'):
    """
    Returns True if the r1 and r2 seem to be the same route, otherwise
    False is returned.
    """
    w = wildcard
    if len(r1) != len(r2):
        return False
    else:
        for i in range(0, len(r1)):
            if r1[i] != r2[i] and not (r1[i] == w or r2[i] == w):
                return False
    return True


def add_edges(G, wildcard = 'q'):
    '''
    Adds edges to a graph G, whose nodes represent routes, when two routes seem
    to be equivalent, i.e., are unambiguously related.
    '''
    nodes = list(G.nodes)
    q_nodes = len(nodes)
    for i in range(0, q_nodes - 1):
        for j in range(i + 1, q_nodes):
            if are_equivalent(nodes[i], nodes[j], wildcard):
                # print(nodes[i], nodes[j])
                G.add_edge(nodes[i], nodes[j])
    return G


def create_graph(routes_list, wildcard = 'q'):
    '''
    Returns a graph where i) nodes are routes and ii) edges between two nodes
    represent that the two routes are unambiguously related.
    '''
    G = nx.Graph()
    G.add_nodes_from(routes_list)
    return add_edges(G, wildcard)


def merge_routes_wcards(datastr, wildcard = 'q'):
    '''
    Returns the sets of (correlated internal) routes after merging routes
    including wildcards and that seem to match.
    '''
    new_sets_routes = []
    G = create_graph([x for s in datastr.data.keys() for x in s], wildcard)
    connected_components = nx.connected_components(G)
    for cc in connected_components:
        if nx.density(G.subgraph(cc)) == 1.0:  # i.e., fully connected graph.
            new_sets_routes.append(frozenset(cc))
        else:
            for route in cc:
                new_sets_routes.append(frozenset([route]))
    return new_sets_routes


def select_best_candidate_route(routes_set, wildcard = 'q'):
    """
    Returns the route with less missing hops from a set of (correlated
    internal) routes.
    """
    return sorted(routes_set, key=lambda x: x.count(wildcard))[0]


def recompute_sets(datastr, new_sets_routes, wildcard = 'q'):
    '''
    Recomputes the sets of correlated internal routes and prefixes when routes
    with wildcards are equivalent, and thus sets can be merged.
    '''
    new_datastr = DataStruct()
    for new_set_routes in new_sets_routes:
        new_set_prefixes = set()
        for original_set_routes in datastr.data.keys():
            if not new_set_routes.isdisjoint(original_set_routes):
                original_set_prefixes = datastr.data[original_set_routes]
                new_set_prefixes = new_set_prefixes.union(original_set_prefixes)
        # new_datastr.data[frozenset(new_set_routes)] = new_set_prefixes
        new_key_route = select_best_candidate_route(new_set_routes, wildcard)
        new_datastr.data[frozenset([new_key_route])] = new_set_prefixes
    return new_datastr

def recompute_structure(datastr, wildcard = 'q'):
    '''
    Recomputes the correlated internal routes and prefixes for a given
    triplet (X, i, e) if while trying to merge the collected internal routes
    including missing hops, a relationship among them is found.
    '''
    new_sets_routes = merge_routes_wcards(datastr, wildcard)
    if datastr.data.keys() == new_sets_routes:
        return datastr
    else:
        return recompute_sets(datastr, new_sets_routes, wildcard)


def merge_wildcards(overall, wildcard = 'q'):
    """
    Recomputes the correlated internal routes and prefixes for every triplet
    (AS, i, e) gathered on a VP basis.
    """
    for key in overall:
        overall[key] = recompute_structure(overall[key], wildcard)
    return overall


def perdestMDA_AS_parallel(dst, confidence, AS, mapper_file, max_diversity=2**8, mapper_format=utils.IP2ASMapper.BDRMAPIT_FORMAT, tmp_folder="tmp-mda", res_folder="mda-traces"):
    """
    Same as perdestMDA_AS, with ips passed in PARALLEL TO SCAMPER
    Returns *all the routes* (according the selected <confidence>)
    inside a given <AS> discovered towards the /24 prefix in which <dst> is located.
    Probing process halts if <max_diversity> routes are discovered (default: 255).
    Raw results are stored in <tmp_folder>.
    <mapper_file> is required to perform ip-to-as mapping.
    """

    mapper = utils.IP2ASMapper(mapper_file, format=mapper_format)

    # diversity hypothesis to rule out.
    # "hops" refers to the original MDA naming (looks for different hops rather than different routes).
    hops = 2  # first hypothesis to rule out: 2 different routes.

    IPs_already_probed = []
    while True:
        IPs_to_probe = mda.getBuddyList(dst, IPs_already_probed, mda.probesToSend(hops, confidence) - len(IPs_already_probed))
        print "hops:", hops
        print "len toProbe:", len(IPs_to_probe)
        pprint(IPs_to_probe)
        # raw_input()

        outfileList = []
        routes = set()
        rounD = 1  # counts iterations. Used to name the files.

        folder = "%s/%s/%s" % (tmp_folder, dst.replace(".", "-"), AS.replace("_", ""))
        outfile_name = "%s_%s_%s" % (dst.replace(".", "-"), AS.replace("_", ""), rounD)
        outfileList.append("%s/%s.warts" % (folder, outfile_name))
        
        # call scamper here
        mda.traceroute(IPs_to_probe, outfile_name, folder=folder, pps=200)

        # load trace
        tt = utils.TraceCampaign("{folder}/{file_name}.adump".format(**{"folder": folder,
                                                                   "file_name": outfile_name})).traces
        for t in tt:
            # apply ip2as mapping
            t.IP2ASMappingAndRelated(mapper)
            
            if AS in t.ASSequence:
                route = t.ASInfo[AS].subpath
                print "ROUTE:", route
                # raw_input()
                routes.add(route)

        IPs_already_probed.extend(IPs_to_probe)

        if len(routes) >= max_diversity:
            break  # stop probing

        elif len(routes) >= hops:
            # more probes to send.
            hops = len(routes) + 1
            rounD += 1

        else:
        # all paths have been found with <confidence>% confidence
            break

    # merge warts. 
    mergedFileName = "%s_%s.warts" % (dst, AS)
    print "outfileList"
    pprint(outfileList)
    if outfileList != []:
        mda.sc_warts_concatenate(outfileList, mergedFileName, res_folder)
    # remove tmp?

    return routes


def perdestMDA_AS(dst, confidence, AS, mapper_file, max_diversity=2**8, mapper_format=utils.IP2ASMapper.BDRMAPIT_FORMAT, tmp_folder="tmp-mda", res_folder="mda-traces"):
    """
    Returns *all the routes* (according the selected <confidence>)
    inside a given <AS> discovered towards the /24 prefix in which <dst> is located.
    Probing process halts if <max_diversity> routes are discovered (default: 255).
    Raw results are stored in <tmp_folder>.
    <mapper_file> is required to perform ip-to-as mapping.
    """

    mapper = utils.IP2ASMapper(mapper_file, format=mapper_format)

    # diversity hypothesis to rule out.
    # "hops" refers to the original MDA naming (looks for different hops rather than different routes).
    hops = 2  # first hypothesis to rule out: 2 different routes.

    IPs_already_probed = []
    while True:
        IPs_to_probe = mda.getBuddyList(dst, IPs_already_probed, mda.probesToSend(hops, confidence) - len(IPs_already_probed))
        print "hops:", hops
        print "len toProbe:", len(IPs_to_probe)
        pprint(IPs_to_probe)
        # raw_input()

        outfileList = []
        routes = set()
        for ip in IPs_to_probe:

            folder = "%s/%s/%s" % (tmp_folder, dst.replace(".", "-"), AS.replace("_", ""))
            outfile_name = "%s_%s_%s" % (dst.replace(".", "-"), AS.replace("_", ""), ip.replace(".", "-"))
            outfileList.append("%s/%s.warts" % (folder, outfile_name))

            # call scamper here
            mda.traceroute(ip, outfile_name, folder=folder)

            # load trace
            t = utils.TraceCampaign("{folder}/{file_name}.adump".format(**{"folder": folder,
                                                                       "file_name": outfile_name})).traces[0]
            # apply ip2as mapping
            t.IP2ASMappingAndRelated(mapper)

            IPs_already_probed.append(ip)

            print AS
            print t.ASSequence
            print AS in t.ASSequence
            
            # raw_input()

            # TODO: AS not in AS sequence can be managed more efficiently?

            if AS in t.ASSequence:
                route = t.ASInfo[AS].subpath
                print "ROUTE:", route
                # raw_input()
                routes.add(route)

        if len(routes) >= max_diversity:
            break  # stop probing

        elif len(routes) >= hops:
            # more probes to send.
            hops = len(routes) + 1

        else:
        # all paths have been found with <confidence>% confidence
            break

    # merge warts. 
    mergedFileName = "%s_%s.warts" % (dst, AS)
    print "outfileList"
    pprint(outfileList)
    if outfileList != []:
        mda.sc_warts_concatenate(outfileList, mergedFileName, res_folder)
    # remove tmp?

    return routes


if __name__ == "__main__":

    mapper_file = "ip2as.20191220.bdrmapit"

    # Input file --> remember: first line of the file is skipped.
    filename = sys.argv[1]
    
    # Initialize the data structure (one TIR per prefix)
    overall, _ = init(filename)
    
    print "before merging"
    pprint(overall)
    for key in overall:
        print(key)
        print
        for key_key in overall[key].data:
            print(key_key)
            pprint(overall[key].data[key_key])
            print
    raw_input()

    overall = merge_wildcards(overall)
    print "after merging"
    pprint(overall)
    # for key in overall:
    #     print(key)
    #     print
    #     for key_key in overall[key].data:
    #         print(key_key)
    #         pprint(overall[key].data[key_key])
    #         print

    sys.exit()
    
    # global variables
    MINIMUM_NUMBER_OF_PREFIXES_TO_PROBE = 3  # number of prefixes to probe in case of no diversity spotted
    #ONLINE_MERGING = True
    ONLINE_MERGING = False

    TMP_FOLDER = "tmp-results-mda"
    RES_FOLDER = "results-mda"

    # MAIN LOOP: for each (AS,i,e)
    # start with the ones that can measured quickly (less doublePs)
    for (AS, i , e) in sorted(overall.keys(), key=lambda x: overall[x].num_2Ps()):
        
        # at each cycle datastr refers to the info related to the specific (AS,i,e)
        datastr = overall[(AS, i, e)]
        exit_from_set = False
        exit_from_prefixes = False
        already_taken_route_sets = set()
        for _ in range(0, len(datastr.data.keys())):

            # According to the current strategy, no specific condition is defined to skip the remaining sets
            # of the (AS,i,e).
            # At least the *minmum amount* of prefixes has to be probed.
            if exit_from_set:
                break
            
            if not ONLINE_MERGING:
                # dict to store temporary data (and add it at the end (OFFLINE))
                route2prefixes_tmp = defaultdict(set)  # maps routes to destinations (prefixes)

            # pick one set of prefixes at random
            random_route_set = random.choice(list(set(datastr.data.keys()).difference(already_taken_route_sets)))
            already_taken_route_sets.add(random_route_set)
            
            #print random_route_set
            
            prefixes = datastr.data[random_route_set]

            already_taken_prefixes = set()
            path_diversity_found = False
            
            for _ in range(0, len(prefixes)):    
                if exit_from_prefixes:
                    break

                # pick one prefix at random
                random_prefix = random.choice(list(prefixes.difference(already_taken_prefixes)))
                already_taken_prefixes.add(random_prefix)


                print "SELECTED PREF", random_prefix
                # raw_input()

                #routes = perdestMDA_AS(random_prefix, 95, AS, mapper_file, max_diversity=2**8, tmp_folder=TMP_FOLDER, res_folder=RES_FOLDER) 
                routes = perdestMDA_AS_parallel(random_prefix, 95, AS, mapper_file, max_diversity=2**8, tmp_folder=TMP_FOLDER, res_folder=RES_FOLDER) 

                pprint(routes)
                
                print len(routes)
                # raw_input()

                if ONLINE_MERGING:
                    # merge newly discovered routes with set of routes previously associated with the same prefix
                    # discovered_routes.union(random_route_set)
                    # add newly discovered routes to the datastr
                    datastr.add(set([random_prefix]), set(routes))
                else:
                    # append to a tmp structure and merge at the end...
                    route2prefixes_tmp[frozenset(routes)].add(random_prefix) 
                


                # exit condition
                if len(routes) > 1:
                    path_diversity_found = True

                # MINIMUM_NUMBER_OF_PREFIXES_TO_PROBE already probed (or ALL, if less than MINIMUM_NUMBER_OF_PREFIXES_TO_PROBE)
                enough_probing_done = len(already_taken_prefixes) == MINIMUM_NUMBER_OF_PREFIXES_TO_PROBE \
                                   or len(already_taken_prefixes) == len(prefixes)

                # no need to go on if 
                # 1) enough probing done OR
                # 2) path diversity found
                exit_from_prefixes = enough_probing_done or path_diversity_found
                
        if not ONLINE_MERGING:
            for r in route2prefixes_tmp:
                datastr.add(route2prefixes_tmp[r], set(r))

    with open("results.testing", "w") as f:
        json.dump(overall, f)
