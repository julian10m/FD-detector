import glob
import sys
import json
import os
from pprint import pprint
import matplotlib.pyplot as plt
import multiprocessing
from functools import partial
from collections import defaultdict
import random
# from tqdm import tqdm


import smartprobing


AFFORDABLE_COST = 5 * (10 ** 5) # max number of traces per vp.
Q_PREFIXES = 4 # number of prefixes to probe per set of correlated prefixes.
Q_TRACES   = 64 # number of traces to send per each prefix to measure.
SHUFFLE_IP_LIST = True

DIR_LABEL = 'D'

def str_ie_data(data):
    pfxs_data = []
    routes_data = []
    tot_pfxs = 0
    for routes, pfxs in data.items():
        tot_pfxs += len(pfxs)
        if DIR_LABEL in pfxs:
            pfxs_data.append(str(len(pfxs)) + '(DIR)')
        else:
            pfxs_data.append(str(len(pfxs)))
        routes_data.append(len(routes))
    return "%s --> %s, %s" % (str(routes_data), str(pfxs_data), tot_pfxs)

def process_input_file(file_path):
    print 'Running init...'
    overall, asie2dir = smartprobing.init(file_path)

    pprint(overall)

    print 'Adding DIRs...'
    for k in sorted(asie2dir.keys()):
        if frozenset(asie2dir[k]) not in overall[k].data:
            overall[k].data[frozenset(asie2dir[k])] = DIR_LABEL
        else:
            overall[k].data[frozenset(asie2dir[k])].add(DIR_LABEL)
    overall = smartprobing.merge_wildcards(overall)

    print 50 * '*'
    for k in sorted(overall):
    # for k in sorted(overall.keys(), key=lambda x: overall[x].num_2Ps()):
        # if k == ('3257', '77.67.123.205', '213.200.119.182'):
        print k, str_ie_data(overall[k].data)
            # pprint(overall[k].data.keys())
    sys.exit()

    vp_data = defaultdict(dict)
    for (AS, i , e) in sorted(overall.keys(), key=lambda x: overall[x].num_2Ps()):
        vp_data[AS][(i, e)] = overall[(AS, i, e)].data
    return vp_data


def prefix_range(D):
    for x in range(0, 256, Q_TRACES):
        if D < x:
            return (x - Q_TRACES, x)
    return (256 - Q_TRACES, 256)
    # if D < 64:
    #     return (0, 64)
    # elif D < 128:
    #     return (64, 128)
    # elif D < 192:
    #     return (128, 192)
    # return (192, 256)


def get_ip_list_from_prefixes(prefixes):
    ip_list = []
    for prefix in prefixes:
        A, B, C, D = prefix.split('.')
        min_D, max_D = prefix_range(int(D))
        for new_D in range(min_D, max_D):
            ip_list.append('{}.{}.{}.{}'.format(A, B, C, new_D))
    if SHUFFLE_IP_LIST:
        random.shuffle(ip_list)
    return ip_list


def write_to_file(output_path, filename, data):
    with open("/".join([output_path, filename]), 'w') as f:
        for piece_of_data in data:
            f.write("{}\n".format(piece_of_data))


def get_str_pfxs(sets_pfxs):
    str_pfxs = []
    for idx in range(len(sets_pfxs)):
        pfxs = sets_pfxs[idx]
        str_pfxs.append(','.join(sorted(pfxs)))
    return '-'.join(str_pfxs)
    # return '-'.join([','.join(pfxs) for pfxs in sets_pfxs])


def prepare_pfxs_data(pfxs_data):
    pfxs_to_trace  = pfxs_data[0]
    sets_corr_pfxs = pfxs_data[1]
    return ([pfx for corr_prfxs in pfxs_to_trace for pfx in corr_prfxs],
            get_str_pfxs(pfxs_to_trace),
            get_str_pfxs(sets_corr_pfxs))


def print_to_output_files(vp, to_trace, output_path):
    ip_list   = []
    extra_ips = []
    out_lines = []
    for AS in to_trace:
        all_ies = [i_e for i_e in to_trace[AS].keys() if i_e != 'cost']
        for i_e in all_ies:
            prfxs_to_trace, str_pfxs, str_pfxs_all = prepare_pfxs_data(to_trace[AS][i_e])
            # print pfxs_to_trace, str_pfxs, str_pfxs_all
            # prfs = ','.join(prfxs_to_trace)
            # out_lines.append(';'.join([vp, AS, i_e[0], i_e[1], prfs]))
            out_lines.append(';'.join([vp, AS, i_e[0], i_e[1], str_pfxs, str_pfxs_all]))
            ip_list += get_ip_list_from_prefixes(prfxs_to_trace)
            if i_e[1] not in extra_ips:  # this checking should always be true...
                extra_ips.append(i_e[1])
    if SHUFFLE_IP_LIST:
        random.shuffle(extra_ips)
    print(vp, 'len(IPs) : {}'.format(len(ip_list)))
    # write_to_file(output_path, vp + '-MDA.ips', extra_ips + ip_list)
    write_to_file(output_path, vp + '.recovery2', out_lines) 


def get_probing_prfxs_and_cost(corr_prfxs):
    if len(corr_prfxs) <= Q_PREFIXES:
        return Q_TRACES * len(corr_prfxs), corr_prfxs
    else:
        prfxs = random.sample(corr_prfxs, Q_PREFIXES)
        return Q_TRACES * Q_PREFIXES, prfxs

    # prfxs = corr_prfxs if len(corr_prfxs) <= Q_PREFIXES else random.sample(corr_prfxs, Q_PREFIXES)
    # return Q_TRACES * Q_PREFIXES, prfxs

    # return Q_TRACES * len(corr_prfxs), corr_prfxs

def get_probing_prfxs_and_cost_IE(ie_data):
    cost_ie = 0
    prefixes_ie = []
    sets_prfxs = []
    for corr_routes in ie_data:
        corr_pfxs = ie_data[corr_routes]
        cost, prefixes = get_probing_prfxs_and_cost(corr_pfxs)
        cost_ie += cost
        prefixes_ie.append(prefixes)
        sets_prfxs.append(corr_pfxs)
    return cost_ie, [prefixes_ie, sets_prfxs]
    # return cost_ie, prefixes_ie


def get_probing_prfxs_and_cost_VP(vp_data):
    cost_vp = 0
    to_trace = defaultdict(dict)
    for AS in vp_data:
        cost_as = 0
        for i_e in vp_data[AS]:
            cost_ie, prefixes_ie = get_probing_prfxs_and_cost_IE(vp_data[AS][i_e])
            cost_as += cost_ie
            to_trace[AS][i_e] = prefixes_ie
            # to_trace[AS][i_e] = [prefixes_ie, vp_data[AS][i_e].values()]
        to_trace[AS]['cost'] = cost_as
        cost_vp += cost_as
    return to_trace, cost_vp


def reduce_cost_VP(vp, cost, to_trace):
    rm_data = defaultdict(dict)
    ASes = sorted(to_trace.keys(), key = lambda AS: to_trace[AS]['cost'])
    while(ASes and cost > AFFORDABLE_COST):
        cost -= to_trace[ASes[-1]]['cost']
        rm_data[vp][ASes[-1]] = to_trace[ASes[-1]]['cost']
        del to_trace[ASes[-1]]
        del ASes[-1]
    return cost, to_trace, rm_data 


def generate_output_file(in_filename, output_path):
    vp = in_filename.split('/')[-1].split('-')[0]
    # vp = in_filename.split('/')[-1].split('.')[0]    
    print(vp)

    vp_data = process_input_file(in_filename)

    out_lines = []
    for AS in vp_data:
        for i_e in vp_data[AS]:
            out_lines.append(';'.join([vp, AS, i_e[0], i_e[1], str(len(vp_data[AS][i_e]))]))
    write_to_file(output_path, vp + '.recovery3', out_lines)
    print 'done for', vp
    return 1, 1

    to_trace, cost = get_probing_prfxs_and_cost_VP(vp_data)  
    new_cost, to_trace, rm_data = reduce_cost_VP(vp, cost, to_trace)
    if rm_data:
        pprint(rm_data)
    if new_cost:
        print_to_output_files(vp, to_trace, output_path)
    print(vp, 'new_cost : {}'.format(new_cost))
    return cost, new_cost


def main_pre_processing_multiprocess(input_files, output_path):
    p  = multiprocessing.Pool()
    worker_function = partial(generate_output_file, output_path = output_path)
    results = p.map(worker_function, input_files)
    p.close()
    p.join()
    sorted_results = sorted(results, key = lambda result: result[0])
    cost_vps     = [x[0] for x in sorted_results]
    new_cost_vps = [x[1] for x in sorted_results]
    plt.scatter([x for x in range(len(cost_vps))], cost_vps)
    plt.scatter([x for x in range(len(new_cost_vps))], new_cost_vps)
    plt.grid(True)
    plt.xlabel('VP')
    plt.ylabel('# Double Ps')
    plt.savefig('new.pdf')


def main_pre_processing_sequential(input_files, output_path):
    results = []
    for filename in input_files:
        results.append(generate_output_file(filename, output_path))


if __name__ == "__main__":
    input_path  = "../nlnog-ring-stuff/LARGE-SCALE-2020/backup_results/pre_processing_input"
    output_path =   "../nlnog-ring-stuff/LARGE-SCALE-2020/backup_results/output_pre_processing"
    input_files = sorted(glob.glob('/'.join([input_path, '*'])))[:1]

    pprint(input_files)

    # Analysis for the paper
    # 
    # input_path  = "../nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/pre_processing_input"
    # output_path = "../nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/MDA-IP-lists"
    # input_files = sorted(glob.glob('/'.join([input_path, '*'])))

    # Analysis for VP in Strasbourg
    # 
    # input_path  = "../nlnog-ring-stuff/LARGE-SCALE-2020/resultsStrasbourg"
    # output_path = "../nlnog-ring-stuff/LARGE-SCALE-2020/resultsStrasbourg"
    # input_files = sorted(glob.glob('/'.join([input_path, 'strasbourg-pre*'])))
    
    # main_pre_processing_multiprocess(input_files, output_path)
    main_pre_processing_sequential(input_files, output_path)








    # main_pre_processing
    
    # input_path = '/'.join([input_path, '*'])
    ## input_path = '/'.join([input_path, '*.ecmp_list'])
    # input_path = '/'.join([input_path, '*liquidtelecom02*'])
    # input_files = sorted(glob.glob(input_path))
    # print(input_files)
    # for input_file in input_files:
        # print(input_file)
        # generate_output_file(input_file, output_path)

        