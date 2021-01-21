import glob
import sys
import json
import os
import networkx as nx
from pprint import pprint
import matplotlib.pyplot as plt
import multiprocessing
from functools import partial
from collections import defaultdict, Counter
import random
# from tqdm import tqdm


import smartprobing
from utils import Trace, TraceCampaign, loop_in_path
import pre_processing

DIR_LABEL = 'D'

def get_vps(vp_list_path):
    try:
        with open(vp_list_path) as vplistf:
            vantagePoints = vplistf.readlines()
        vantagePoints = [x.strip() for x in vantagePoints if not x.startswith("#")]
    except:
        vantagePoints = None
    return vantagePoints


def get_list_pfxs(str_pfxs):
    return [set(pfxs.split(',')) for pfxs in str_pfxs.split('-')]


def get_data_structure(recovery_data_path):
    vp_data = defaultdict(dict)
    with open(recovery_data_path) as recovery_file:
        for line in recovery_file:
            vp, AS, i, e, pfxs_str, corr_pfxs_str = line.strip().split(';')
            i_e = (i, e)
            traced_pfxs = get_list_pfxs(pfxs_str)
            corr_pfxs = get_list_pfxs(corr_pfxs_str)
            if i_e not in vp_data[AS]:
                vp_data[AS][i_e] = {}
            for j in range(len(traced_pfxs)):
                t_pfxs = traced_pfxs[j]
                c_pfxs = corr_pfxs[j]                
                if t_pfxs and t_pfxs.issubset(c_pfxs):
                    if frozenset(c_pfxs) in vp_data[AS][i_e]:
                        print 'WARNING: c_pfxs repeated??'
                    # vp_data[AS][i_e][frozenset(c_pfxs)] = t_pfxs
                    vp_data[AS][i_e][frozenset(c_pfxs)] = c_pfxs
    return vp_data



def are_correlated(rs1, rs2):
    if rs1.intersection(rs2):
        return True
    for r1 in rs1:
        for r2 in rs2:
            if smartprobing.are_equivalent(r1, r2):
                return True
    return False



def merge_correlated_ie(ie_data):
    m_sets = {}
    for pfxs, routes in ie_data.items():
        intersecting_keys = [k for k in m_sets if are_correlated(m_sets[k], routes)]
        new_key = set()
        for k in intersecting_keys:
            new_key = new_key.union(k)
        new_key = new_key.union(pfxs)
        new_value = set()
        for k in intersecting_keys:
            new_value = new_value.union(m_sets[k])
        new_value = new_value.union(routes)
        for k in intersecting_keys:
            del m_sets[k]
        new_key = frozenset(new_key)
        m_sets[new_key] = new_value            
    return m_sets


def merge_sets(vp_data):
    results = defaultdict(dict)
    for AS in vp_data:
        results_AS = defaultdict(int)
        for i_e in vp_data[AS]:
            # pprint(i_e)
            # pprint(str_ie_data(vp_data[AS][i_e]))
            vp_data[AS][i_e] = merge_correlated_ie(vp_data[AS][i_e])
            for corr_pfxs in vp_data[AS][i_e]:
                vp_data[AS][i_e][corr_pfxs], q_ccs, q_unambiguous, q_len3 = reduce_routes(vp_data[AS][i_e][corr_pfxs])
            # pprint(str_ie_data(vp_data[AS][i_e]))
            # print 25 * '*'
    return vp_data


def reduce_routes(corr_routes):
    remaining_routes = set()
    G = smartprobing.create_graph(list(corr_routes))
    connected_components = nx.connected_components(G)
    q_unambiguous = 0
    q_ccs = 0
    q_len3 = 0
    for cc in connected_components:
        q_ccs += 1
        # if len(G.subgraph(cc).nodes) == 1:
        #     q_unambiguous += 1
        #     for route in cc:
        #         remaining_routes.add(route)
        if nx.density(G.subgraph(cc)) == 1.0:  # i.e., fully connected graph.
            q_unambiguous += 1
            best_route = smartprobing.select_best_candidate_route(cc)
            remaining_routes.add(best_route)
        else:
            for route in cc:
                remaining_routes.add(route)
            if all(map(lambda x: x == 3, [len(r) for r in cc])):
                q_len3 += 1
            # pprint(cc)
    return remaining_routes, q_ccs, q_unambiguous, q_len3


def compute_wildcards_rate(vp_data, vp_nick):
    out_folder = '../nlnog-ring-stuff/LARGE-SCALE-2020/backup_results/stats_wildcards'
    with open("%s/%s" % (out_folder, vp_nick + "-wildcards.stats"), 'w') as f:
        for AS in vp_data:
            for i_e in vp_data[AS]:
                ie_data = vp_data[AS][i_e]
                wildcards_data = []
                for corr_pfxs in ie_data:
                    qRs_withWs = sum(map(lambda r: 'q' in r, ie_data[corr_pfxs]))
                    qRs = len(ie_data[corr_pfxs])
                    wildcards_data.append(':'.join([str(qRs_withWs), str(qRs)]))
                wildcards_data = ','.join(wildcards_data)
                out_line = ';'.join([vp_nick, AS, i_e[0], i_e[1], wildcards_data])
                f.write('{}\n'.format(out_line))


def best_routes_selection(vp_data, vp_nick):
    '''
    Returns the sets of (correlated internal) routes after merging routes
    including wildcards and that seem to match.
    '''
    compute_wildcards_rate(vp_data, vp_nick)

    out_folder = '../nlnog-ring-stuff/LARGE-SCALE-2020/backup_results/stats_wildcards'
    with open("%s/%s" % (out_folder, vp_nick + "-index.stats"), 'w') as f:
        for AS in vp_data:
            for i_e in vp_data[AS]:
                q_multiroute_sets = 0
                ccs_data = []
                for corr_pfxs in vp_data[AS][i_e]:
                    corr_routes = vp_data[AS][i_e][corr_pfxs]
                    if len(corr_routes) > 1:
                        vp_data[AS][i_e][corr_pfxs], q_ccs, q_unambiguous, q_len3 = reduce_routes(corr_routes)
                        ccs_data.append(':'.join([str(q_unambiguous), str(q_len3), str(q_ccs)]))
                ccs_data = ','.join(ccs_data)                        
                f.write('{};{};{};{};{};{}\n'.format(vp_nick,
                                                  AS,
                                                  i_e[0],
                                                  i_e[1],
                                                  len(vp_data[AS][i_e]),
                                                  ccs_data))
                #     print 25 * '-'
                # pprint(str_ie_data(vp_data[AS][i_e]))
                # print 50 * '*'

    return vp_data


def add_IRs_to_structure(vp_data, vp_campaign):
    void_couples = []
    for AS in vp_data:
        for i_e in vp_data[AS]:
            for c_pfxs in vp_data[AS][i_e]:
                t_pfxs = vp_data[AS][i_e][c_pfxs]
                vp_data[AS][i_e][c_pfxs] = set()
                for pfx in t_pfxs:
                    A, B, C, D = pfx.split('.')
                    pfx_base = '.'.join([A, B, C])
                    min_D, max_D = pre_processing.prefix_range(int(D))
                    for new_D in range(min_D, max_D):
                        new_IP = '.'.join([pfx_base, str(new_D)])
                        try:
                            IR = vp_campaign.tracesByDestination[new_IP].getSubTrace(i_e[0], i_e[1])
                            if len(IR) > 2:
                                vp_data[AS][i_e][c_pfxs].add(IR)
                            else:
                                if (AS, i_e) not in void_couples:
                                    void_couples.append((AS, i_e))
                                break
                        except:
                            pass

                        # if new_IP in vp_campaign.tracesByDestination:
                        #     if AS == '3257':
                        #         if i_e == ('216.221.158.121', '89.149.185.230'):
                        #             pprint(pfx_base)

    for (AS, i_e) in void_couples:
        del vp_data[AS][i_e]
        if not vp_data[AS]:
            del vp_data[AS]
    return vp_data


def str_ie_data(data):
    pfxs_data = []
    routes_data = []
    for pfxs, routes in data.items():
        if DIR_LABEL in pfxs:
            pfxs_data.append(str(len(pfxs)) + '(DIR)')
        else:
            pfxs_data.append(str(len(pfxs)))
        routes_data.append(len(routes))
    return "%s --> %s" % (str(routes_data), str(pfxs_data))


def print_structure(vp_data):
    for AS in vp_data:
        print 50 * '*'
        print AS
        for i_e in vp_data[AS]:
            print 25 * "#"
            print '{};{};{}'.format(AS, i_e[0], i_e[1])
            pprint(str_ie_data(vp_data[AS][i_e]))
            for c_pfxs in vp_data[AS][i_e]:
                print c_pfxs
                pprint(vp_data[AS][i_e][c_pfxs])

def get_filename(file_path, filename_extension):
    try:
        return glob.glob('/'.join([file_path, filename_extension]))[0]
    except:
        return None


def get_dir(vp_campaign, i_e):
    try:       
        t = vp_campaign.tracesByDestination[i_e[1]]
        if t.destReplied == 'R':
            DIR = list(t.getSubTrace(i_e[0], t.hops[len(t.hops)-1][0]))
            for _ in range(len(t.hops) + 1, t.destDistance):
                DIR.append('q')
            DIR.append(t.destination)
            if not loop_in_path(DIR):
                return tuple(DIR)
    except:
        return None
    return None


def purge_data(vp_data, vp_campaign):
    void_couples = []
    for AS in vp_data:
        for i_e in vp_data[AS]:
            void_corr_pfxs = [corr_pfxs for corr_pfxs in vp_data[AS][i_e] if not vp_data[AS][i_e][corr_pfxs]]
            for corr_pfxs in void_corr_pfxs:
                del vp_data[AS][i_e][corr_pfxs]
            if not vp_data[AS][i_e]:
                void_couples.append((AS, i_e))
                continue
            if sum([len(corr_pfxs) for corr_pfxs in vp_data[AS][i_e]]) < 100:
                void_couples.append((AS, i_e))
                continue
            DIR = get_dir(vp_campaign, i_e)
            if DIR:
                vp_data[AS][i_e][DIR_LABEL] = set([DIR])
            else:
                void_couples.append((AS, i_e))
    for (AS, i_e) in void_couples:
        del vp_data[AS][i_e]
        if not vp_data[AS]:
            del vp_data[AS]
    return vp_data


def generate_output_file(vp_data, vp, output_path):
    out_lines = []
    for AS in vp_data:
        for i_e in vp_data[AS]:
            q_prfxs = []
            for idx, corr_pfxs in enumerate(vp_data[AS][i_e]):
                if DIR_LABEL in corr_pfxs:
                    dir_idx = str(idx)
                    q_prfxs.append(str(len(corr_pfxs) - 1))
                else:
                    q_prfxs.append(str(len(corr_pfxs)))
            q_prfxs_str = ','.join(q_prfxs)
            out_lines.append(';'.join([vp, AS, i_e[0], i_e[1], q_prfxs_str, dir_idx]))
    pre_processing.write_to_file(output_path, vp + '.results', out_lines)


def analyze_vp(vp, recovery_data_path, MDA_data_path, output_path):
    # print "Analyzing {}...".format(vp)
    vp_nick = vp.split('.')[0]
    
    # print "Reading recovery data and generating structure..."
    recovery_filename = get_filename(recovery_data_path, vp_nick + '.recovery2')
    if not recovery_filename:
        # print '\tError: No adump file!!'
        return False
    vp_data = get_data_structure(recovery_filename)

    # for AS in vp_data:
    #     for i_e in vp_data[AS]:
    #         print AS, i_e
    #         pprint(str_ie_data(vp_data[AS][i_e]))

    # print "Reading adump data..."
    vp_dump_file = get_filename(MDA_data_path, vp + "-MDA-*.adump")
    if not vp_dump_file:
        # print '\tError: No adump file!!'
        return False
    vp_campaign = TraceCampaign(vp_dump_file)

    # print "Adding IRs to structure..."
    vp_data = add_IRs_to_structure(vp_data, vp_campaign)

    # for AS in vp_data:
    #     for i_e in vp_data[AS]:
    #         print AS, i_e
    #         pprint(str_ie_data(vp_data[AS][i_e]))

    # print "Adding DIRs and Purging (i, e) couples with missing DIRs/TIRs..."
    vp_data = purge_data(vp_data, vp_campaign)
    if not vp_data:
        # print 'All data was purged :( ...'
        return False
    del vp_campaign

    print(vp_nick)
    # print "Selecting best routes..."
    # vp_data = best_routes_selection(vp_data, vp_nick)

    # return True

    # print "Merging sets..."

    # for AS in vp_data:
    #     for i_e in vp_data[AS]:
    #         print(str_ie_data(vp_data[AS][i_e]))
    #         pprint(vp_data[AS][i_e].values())

    vp_data = merge_sets(vp_data)
    
    # for AS in vp_data:
    #     for i_e in vp_data[AS]:
    #         print(str_ie_data(vp_data[AS][i_e]))


    f = open('data_dist_s_no_best_route_selection', 'a')
    for AS in vp_data:
        for i_e in vp_data[AS]:
            f.write('{}\n'.format(len(vp_data[AS][i_e])))
    f.close()


    # f = open('data_detouring_couples', 'a')
    # for AS in vp_data:
    #     for i_e in vp_data[AS]:
    #         q_prfxs = []
    #         for idx, corr_pfxs in enumerate(vp_data[AS][i_e]):
    #             if DIR_LABEL in corr_pfxs:
    #                 dir_idx = idx
    #                 if len(corr_pfxs) < float(sum([len(p) for p in vp_data[AS][i_e]]))/1.1:
    #                     f.write("{};{};{};{};  {}".format(vp_nick, AS, i_e[0], i_e[1], str_ie_data(vp_data[AS][i_e])))
    #                     if sum([len(r) for r in vp_data[AS][i_e].values()]) == 2:
    #                         f.write('--len:2')
    #                         len_DIR = len(list(vp_data[AS][i_e][corr_pfxs])[0])
    #                         for pfxs in vp_data[AS][i_e]:
    #                             if DIR_LABEL not in pfxs:
    #                                 if len(list(vp_data[AS][i_e][pfxs])[0]) > len_DIR:
    #                                     f.write('--longer')
    #                                     f.write("     {}\n".format(vp_data[AS][i_e][corr_pfxs]))
    #                                     f.write("     {}".format(vp_data[AS][i_e][pfxs]))
    #                                 break
    #                     f.write('\n')
    # f.close()

                        # print(vp_nick, AS, i_e, idx, [(len(r), len(p)) for p, r in vp_data[AS][i_e].items()])





    # generate_output_file(vp_data, vp_nick, output_path)
    print 'Done for {}...'.format(vp_nick)
    return True

def main_FD_verdict_sequential(vps, recovery_data_path, MDA_data_path, output_path):
    for vp in vps:
        status = analyze_vp(vp, recovery_data_path, MDA_data_path, output_path)

def main_FD_verdict_multiprocess(vps, recovery_data_path, MDA_data_path, output_path):
    p  = multiprocessing.Pool(3)
    worker_function = partial(analyze_vp, 
                              recovery_data_path = recovery_data_path,
                              MDA_data_path = MDA_data_path,
                              output_path = output_path)
    results = p.map(worker_function, vps)
    p.close()
    p.join()


if __name__ == "__main__":
    vp_list_path       = "../nlnog-ring-stuff/LARGE-SCALE-2020/nlnog-systematic-selection-20191219.nodes"
    recovery_data_path = "../nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/MDA-IP-lists"
    MDA_data_path      = "../nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/MDA-campaign-results"
    output_path        = "../nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/pre_results"
    
    vps = get_vps(vp_list_path)
    # vps = [vp for vp in vps if 'iucc01' in vp]
    if not vps:
        print 'Error reading the VP list...'
        sys.exit()
    # vps = ['mdbrasil01.ring.nlnog.net']


    # main_FD_verdict_multiprocess(vps, recovery_data_path, MDA_data_path, output_path)
    main_FD_verdict_sequential(vps, recovery_data_path, MDA_data_path, output_path)