import sys
import matplotlib.cm as cm
import glob
from collections import defaultdict, Counter, OrderedDict
from pprint import pprint
import matplotlib.pyplot as plt
import matplotlib.ticker
import numpy as np

WIDTH = 4
BARS_SEPARATION_FACTOR = 1.5

def read_file(filename):
    data_file = defaultdict(dict)
    with open(filename) as f:
        for line in f:
            vp, AS, i, e, q_prfxs_str, dir_idx = line.strip().split(';')
            q_prfxs = [int(q) for q in q_prfxs_str.split(',')]
            q_prfxs.append(int(dir_idx))
            data_file[AS][(i, e)] = q_prfxs
    return vp, data_file

def read_input_files(input_files_path):
    data = defaultdict(dict)
    for filename in input_files_path:
        vp, data_file = read_file(filename)
        data[vp] = data_file
    return data

def reindex_by_AS(data):
    reindexed_data = defaultdict(dict)
    for vp in data:
        for AS in data[vp]:
            if vp not in reindexed_data[AS]:
                reindexed_data[AS][vp] = defaultdict(list)
            for i_e in data[vp][AS]:
                reindexed_data[AS][vp][i_e] = data[vp][AS][i_e]
    return reindexed_data


def analyze_AS(AS, as_data):
    tot_ies = sum([len(as_data[vp].keys()) for vp in as_data])
    qConsistent = 0
    s = defaultdict(dict)
    inc_rate = []
    qDIR = []
    q_p = []
    q_p_inc = []
    i_database = defaultdict(list)
    for vp in as_data:
        for i_e in as_data[vp]:
            i_p = i_e[0]
            q_prfxs = as_data[vp][i_e]
            q_p += q_prfxs[:-1]
            # if any([q > 10000 for q in q_prfxs]):
                # print vp, AS, i_e, q_prfxs
            if len(q_prfxs) == 2:
                qDIR.append(1)
                qConsistent += 1
                i_database[i_p].append(0)
            else:
                after_h = np.array(q_prfxs[:-1], dtype = 'f') / sum(q_prfxs[:-1])
                qDIR.append(after_h[q_prfxs[-1]])
                ok = True
                for idx in range(len(after_h)):
                    if after_h[idx] > 0.8:
                        if idx != q_prfxs[-1]:
                            inc_rate.append(after_h[idx])
                            q_p_inc.append((i_p, q_prfxs[idx]))
                            i_database[i_p].append(after_h[idx])
                            ok = False
                        break
                if ok:
                    qConsistent += 1
                    i_database[i_p].append(0)
                else:
                    pass
                    # if AS == '2914':
                    #     print(AS, vp)
                    # pprint(i_e)
                    # pprint(q_prfxs)
                    # pprint(after_h)
            if i_e not in s[vp]:
                s[vp][i_e] = 0                    
            s[vp][i_e] = len(q_prfxs) - 1

    # print tot_ies, qConsistent, s
    if tot_ies - qConsistent > 40:
        print 'this is the very weird case', AS
    return tot_ies, qConsistent, s, inc_rate, qDIR, q_p, q_p_inc, i_database


def genearte_plots(all_data):
    r = []
    s_tot = []
    inc_rates = []
    DIR_tot = []
    q_tot = []
    q_p_inc_tot = []
    i_database = defaultdict(dict)
    for AS in all_data:
        tot_ies, qConsistent, s, inc_rate, qDIR, q_p, q_p_inc, i_data = analyze_AS(AS, all_data[AS])
        r.append((tot_ies, qConsistent, tot_ies - qConsistent, float(tot_ies - qConsistent) / tot_ies, AS))
        s_tot.append((AS, s))
        inc_rates += inc_rate
        DIR_tot += qDIR
        q_tot += q_p
        i_database[AS] = i_data
        if q_p_inc:
            q_p_inc_tot.append((AS, q_p_inc))

    r = sorted(r, key = lambda result: result[-2])
    t = [x[0] for x in r]
    c = [x[1] for x in r]
    iii = [x[2] for x in r]
    to_study = [x[3] for x in r]
    ASes = [x[4] for x in r]
    # s = sorted(s_tot)
    inc_rates = sorted(inc_rates)
    DIR_tot = sorted(DIR_tot)
    q_tot = sorted(q_tot)
    print len(to_study), len(filter(None, to_study))


    to_plot = defaultdict(list)
    zeros =[]
    ones=[]
    other = []
    q_egresses = []
    for AS in i_database:
        for i in i_database[AS]:
            inc_rate_e = i_database[AS][i]
            if sum(inc_rate_e):
                q_egresses.append(len(inc_rate_e))
                zeros.append(100. * sum([1 for r in inc_rate_e if r <= 0.01]) / len(inc_rate_e))
                ones.append(100.0 * sum([1 for r in inc_rate_e if r >= 0.99]) / len(inc_rate_e))
                other.append(100.0 * sum([1 for r in inc_rate_e if r >0.01 and r < 0.99]) / len(inc_rate_e))
                # to_plot[AS].append((len(inc_rate_e), zeros, other, ones))
                # pprint([len(q_egresses), inc_rate_e])
    idxs = np.array([x for x in range(len(ones))])
    # for AS in to_plot:    
    pprint(zeros[:5])
    pprint(other[:5])
    pprint(ones[:5])
    barWidth = 0.85

    zeros, other, ones, q_egresses= zip(*sorted(zip(zeros, other, ones, q_egresses)))

    fig, ax = plt.subplots(figsize=(10,5))
    ax2 = ax.twinx()

    
    ax.bar(idxs, ones, color='red', alpha = 0.8, edgecolor='black', label = 'FDs $\geq 99\%$', width=barWidth)
    ax2.plot(idxs, q_egresses, 'bo')
    # # # Create green Bars
    # ax.bar(idxs, zeros, color='w', alpha = 0.6, edgecolor='k', width=barWidth, label = 'FDs $\leq 1\%$' )
    # # # Create orange Bars
    # ax.bar(idxs, other, bottom=zeros, color='green', edgecolor='black', width=barWidth)
    # # # Create blue Bars
    # ax.bar(idxs, ones, bottom=[i+j for i,j in zip(zeros, other)], color='red', alpha = 0.8, edgecolor='black', label = 'FDs $\geq 99\%$', width=barWidth)
    
    
    ax2.set_yscale('log')
    # # Custom x axis
    # plt.xticks(r, names)
    # plt.xlabel("group")

    plt.xlim([0-barWidth, len(ones)-1+barWidth])
    # plt.show()

    plt.grid(True)
    ax.set_xlabel('Ingress-ASBR subject to FDs', fontsize = 22)
    ax.set_ylabel('Fraction of Egress-ASBRs\nsubject to FDs [%]', fontsize = 22, color = 'r')
    ax2.set_ylabel("Egress-ASBRs", fontsize = 22, color = 'b')

    # labels = [item.get_text() for item in ax.get_xticklabels()]
    # ax.set_xticklabels(labels)

    major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) * 100
    minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9]) * 100
    ax.set_yticks(major_y_ticks)
    ax.set_yticks(minor_y_ticks, minor=True)
    import matplotlib.ticker as mtick

    # ax.xaxis.set_major_formatter(mtick.PercentFormatter())
    # ax.set_axisbelow(True)
    # # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    ax2.grid(False)
    # # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)

    

    ax.tick_params(axis='y', labelcolor='red')
    ax.yaxis.label.set_color('red')    
    ax.spines['left'].set_color('red')
    ax.spines['right'].set_color('blue')
    ax2.spines['right'].set_color('blue')
    ax2.spines['left'].set_color('red')
    ax2.tick_params(axis='y', labelcolor='blue')

    major_y_ticks = 100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    minor_y_ticks = 100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    ax.set_yticks(major_y_ticks)
    ax.set_yticks(minor_y_ticks, minor=True)

    ax.set_axisbelow(True)
    # And a corresponding grid
    ax.grid(axis='y', which='both')
    # Or if you want different settings for the grids:
    ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)

    ax2.grid(axis='y', which='major', alpha=0.5, linestyle='--', linewidth=0.5)
    ax2.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)

    ax.tick_params(which='minor', # Options for both major and minor ticks
                    top=False, # turn off top ticks
                    left=False, # turn off left ticks
                    right=False,  # turn off right ticks
                    bottom=False) # turn off bottom ticks

    ax.xaxis.set_tick_params(labelsize=22)
    ax.yaxis.set_tick_params(labelsize=22)
    ax2.xaxis.set_tick_params(labelsize=22)
    ax2.yaxis.set_tick_params(labelsize=22)
    
    # ax.set_xticklabels(list(np.array([x+1 for x in range(len(zeros))], dtype = 'f')/len(zeros))[::10])
    # ax2.grid(False)
    # ax.legend(loc="center left", bbox_to_anchor = (0,0,1,1), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16})
    # ax.set_zorder()
    ax.set_ylim((0, 100))
    ax2.set_ylim(top=100)
    # ax.set_ylim(top=100)
    # ax2.set_ylim(top=100)
    # plt.ylim(top=100)
        # , bbox_to_anchor=(1, 0.5),
    plt.tight_layout()
    plt.savefig('flag.pdf')
    # sys.exit()

    ####################################### q prefixes  #######################################
    ####################################### q prefixes #######################################
    ####################################### q prefixes #######################################

    colors = cm.hsv(np.linspace(0.1, 0.9, len(q_p_inc_tot)))
    hatches = ('//', '\\\\', '----', 'xx')
    
    fig, ax = plt.subplots(1, figsize=(21, 5))

    reformulated_data = defaultdict(dict)
    for (AS, d) in q_p_inc_tot:
        for (i_p, qp) in d:
            if i_p not in reformulated_data[AS]:
                reformulated_data[AS][i_p] = []
            reformulated_data[AS][i_p].append(qp)
        for i_p in reformulated_data[AS]:
            reformulated_data[AS][i_p] = sorted(reformulated_data[AS][i_p])[::-1]

    qAS = []
    for AS in reformulated_data:
        q = 0
        for i_p in reformulated_data[AS]:
            q += sum(reformulated_data[AS][i_p])
        qAS.append((AS, q))

    qAS = sorted(qAS, key = lambda v: v[-1])[::-1]
    # pprint(qAS)

    # pprint(reformulated_data)

    # ind = 0
    # for n_as, data in enumerate(q_p_inc_tot):
    #     AS = data[0]
    #     q_p_inc = data[1]
    #     for p in q_p_inc:
    #         plt.bar(ind,
    #             p,
    #             width = WIDTH,
    #             color = colors[n_as],
    #             hatch = hatches[n_as % len(hatches)],
    #             edgecolor='black',
    #             linewidth = 1,
    #             label= 'AS' + str(AS))
    #         ind += WIDTH
    #     ind += 2*WIDTH

    ind = 0
    AS_sep = []
    Couple_sep = []
    for n_as, (asn, q) in enumerate(qAS):
        ips_order = [(i_p, sum(reformulated_data[asn][i_p])) for i_p in reformulated_data[asn]]
        ips_order = sorted(ips_order, key = lambda v: v[-1])[::-1]
        for (i_p, q) in ips_order:
            for p in reformulated_data[asn][i_p]:
                plt.bar(ind,
                        p,
                        width = WIDTH,
                        color = colors[n_as],
                        hatch = hatches[n_as % len(hatches)],
                        edgecolor='black',
                        linewidth = 1,
                        label= 'AS' + str(asn))
                ind += WIDTH
            Couple_sep.append(ind)
            ind += WIDTH
        AS_sep.append(ind)            
        ind += 2 * WIDTH
 
    for xx in Couple_sep:
        plt.axvline(xx, alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    for xx in AS_sep:
        plt.axvline(xx, alpha=1.0, color='k', linestyle='--', linewidth=2)

    plt.grid(True)
    plt.xlabel('ASBR-couples grouped by the same ingress-ASBR', fontsize = 22)
    ax.xaxis.set_label_coords(0.5, -0.05)
    # text = plt.text(0.5,0,'Couples (i, e) with FDs', transform=ax.transAxes, ha = 'center', va = 'center')
    plt.ylabel('Prefixes subject to FDs', fontsize = 22)
    ax.set_yscale('log')
    # plt.show()
    # q_p_inc_tot = sorted(q_p_inc_tot, key = lambda data: sum(data[1]))[::-1]
    # pprint(q_p_inc_tot)
    # sys.exit()
    # ind = 0
    # for n_as, data in enumerate(q_p_inc_tot):
    #     AS = data[0]
    #     q_p_inc = data[1]
    #     for p in q_p_inc:
    #         plt.bar(ind,
    #             p,
    #             width = WIDTH,
    #             color = colors[n_as],
    #             hatch = hatches[n_as % len(hatches)],
    #             edgecolor='black',
    #             linewidth = 1,
    #             label= 'AS' + str(AS))
    #         ind += WIDTH
    #     ind += 2*WIDTH

    # plt.grid(True)
    # plt.xlabel('Per couple [ID]', fontsize = 16)
    # plt.ylabel('qpref with FDs', fontsize = 16)
    # ax.set_yscale('log')
    # major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) 
    # minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9]) 
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    ax.set_axisbelow(True)
    # # And a corresponding grid
    ax.grid(axis='y', which='both')
    ax.grid(axis='x', which='both')
    # # Or if you want different settings for the grids:
    ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.tick_params(which='both', # Options for both major and minor ticks
                    top=False, # turn off top ticks
                    left=False, # turn off left ticks
                    right=False,  # turn off right ticks
                    bottom=False,
                    labelbottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=)
    ax.yaxis.set_tick_params(labelsize=22)
    # fig.set_size_inches(6.5, 4.5)

    plt.gca().set_xlim(left=0-2*WIDTH)
    plt.gca().set_xlim(right=ind)

    handles, labels = plt.gca().get_legend_handles_labels()
    by_label = OrderedDict(zip(labels, handles))

    plt.legend(by_label.values(), by_label.keys(), loc="upper right",
               bbox_to_anchor=(1, 1.05), fancybox=True, shadow=True,
               handletextpad=0.1, columnspacing=0.2, handlelength=0.3,
               edgecolor='k', prop={'size': 20}, ncol=13)
    # fig.set_size_inches(21, 5.5)
    plt.tight_layout()
    plt.savefig('ingress_egress_prefixes_FDs.pdf')
    plt.show()


    ####################################### subplots  q inc + % #######################################
    ####################################### subplots  q inc + % #######################################
    ####################################### subplots  q inc + % #######################################

    # fig, (ax1, ax2) = plt.subplots(nrows=2, figsize=(10, 4))
    # x_axis = np.array([x + 1 for x in range(len(to_study))])    
    # # ax1.scatter(x_axis, 100 * np.array(to_study))
    # # ax2.plot(x_axis, i, 'ro')
    # ax1.bar(100* x_axis / len(x_axis), 100 * np.array(to_study), color = 'b', label = 'Relative [%]')
    # ax2.bar(x_axis, i, color = 'r', label = 'Absolute [1]')
    # # ax2.set_yticks(np.linspace(ax2.get_yticks()[0], ax2.get_yticks()[-1], len(ax1.get_yticks())))
    # plt.grid(True)
    # plt.title('')
    # plt.xlabel('AS [ID]', fontsize = 16)
    # ax1.set_ylabel('Relative [%]', fontsize = 16)
    # ax2.set_ylabel('Absolute', fontsize = 16)
    # # fig.text(0.02, 0.5, 'Couples (i, e) with FDs', ha='center', va='center', rotation='vertical', fontsize = 16)
    # # plt.gca().set_xlim(left=0.5)
    # # plt.gca().set_xlim(right=27.5)
    # # plt.gca().set_xlim(left=29)
    # ax1.set_xlim(left=29)
    # ax2.set_xlim(left=29)
    # ax1.set_xlim(right=54.5)
    # ax2.set_xlim(right=54.5)
    
    # idx = [x_axis[j] for j in range(len(x_axis)) if i[j]]
    # asL = [ASes[j] for j in range(len(ASes))  if i[j]]
    # ax2.set_xticks(idx,minor=False)
    # ax2.set_xticklabels(asL,rotation=90,minor=False)
    # ax2.tick_params(which='major', labelsize=6)

    # # labels = [item.get_text() for item in ax.get_xticklabels()]
    # ax2.set_xticklabels(ASes)
    # # for ax in [ax1, ax2]:
    # # ax.set_xticks([55, 65, 75, 85, 95], minor=True)
    # # major_y_ticks = 100 * np.array([0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    # # minor_y_ticks = 100 * np.array([0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95])
    # ax1.set_yticks(100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]))
    # ax1.set_yticks(100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9]), minor=True)

    # ax2.set_yticks(100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])/2)
    # ax2.set_yticks(100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])/2, minor=True)
    # for ax in [ax1, ax2]:
    #     ax.set_axisbelow(True)
    #     ax.grid(axis='y', which='both')
    #     ax.grid(axis='x', which='both')
    #     ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    #     ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    #     ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    #     ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    #     ax.tick_params(which='minor', # Options for both major and minor ticks
    #                     top=False, # turn off top ticks
    #                     left=False, # turn off left ticks
    #                     right=False,  # turn off right ticks
    #                     bottom=False) # turn off bottom ticks


    # ax2.xaxis.set_tick_params(labelsize=16)
    # ax1.yaxis.set_tick_params(labelsize=16)
    # ax2.yaxis.set_tick_params(labelsize=16)
    
    # # handles, labels = plt.gca().get_legend_handles_labels()
    # # by_label = OrderedDict(zip(labels, handles))
    # ax1.legend(loc="upper center", bbox_to_anchor=(.5, 1.05), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # ax2.legend(loc="upper center", bbox_to_anchor=(.5, 1.05), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # fig.set_size_inches(6.5, 6.5)
    # plt.tight_layout()
    # plt.savefig('pr5.pdf')
    # plt.show()

    

    ####################################### q inc + %  #######################################
    ####################################### q inc + % #######################################
    ####################################### q inc + % #######################################

    # fig, ax1 = plt.subplots(1, figsize=(10, 4))
    # ax2 = ax1.twinx()
    # x_axis = 100 * np.array([x + 1 for x in range(len(to_study))]) / len(to_study)
    # ax1.scatter(x_axis, to_study)
    # ax2.plot(x_axis, i, 'ro')
    # # ax2.set_yticks(np.linspace(ax2.get_yticks()[0], ax2.get_yticks()[-1], len(ax1.get_yticks())))
    # plt.grid(True)
    # plt.title('')
    # plt.xlabel('ASes [%]')
    # plt.ylabel('Couples (i, e) [%]')
    # plt.gca().set_xlim(left=53)
    # plt.tight_layout()
    # plt.savefig('pr2.pdf')
    # # plt.show()

    ####################################### q inc  #######################################
    ####################################### q inc  #######################################
    ####################################### q inc  #######################################

    # fig, ax = plt.subplots(1, figsize=(10, 4))
    # ax.scatter([x for x in range(len(i))], i)
    # # plt.grid(True)
    # plt.title('Couples suffering FDs')
    # plt.xlabel('AS [ID]')
    # plt.ylabel('Abs number')
    # # ax.set_yscale('log')
    # plt.savefig('abs.pdf')
    # plt.show()
    
    ####################################### Scatter couples % in AS  #######################################
    ####################################### Scatter couples % in AS  #######################################
    ####################################### Scatter couples % in AS  #######################################

    # plt.figure()
    # fig, ax = plt.subplots()
    # x_axis = 100 * np.array([x + 1 for x in range(len(to_study))]) / len(to_study)
    # plt.plot(x_axis, np.array(to_study) * 100, 'bo')
    # plt.xlabel('ASes [%]', fontsize = 16)
    # plt.ylabel('Couples (i, e) with FDs in AS [%]', fontsize = 16)
    # plt.gca().set_xlim(left=53)
    # plt.gca().set_xlim(right=101)

    # ax.set_xticks([55, 65, 75, 85, 95], minor=True)
    # # major_y_ticks = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    # # minor_y_ticks = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95]
    # major_y_ticks = 100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    # minor_y_ticks = 100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=16)
    # ax.yaxis.set_tick_params(labelsize=16)
    # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()
    # plt.savefig('percentage_couples_inc_per_AS.pdf')
    # # plt.show()

    ####################################### Scatter + colors couples % in AS  #######################################
    ####################################### Scatter + colors couples % in AS  #######################################
    ####################################### Scatter + colors couples % in AS  #######################################

    # plt.figure()
    # fig, ax = plt.subplots(1, figsize=(10, 4))
    # x_axis = 100 * np.array([x + 1 for x in range(len(to_study))]) / len(to_study)

    # t1 = [x for x in range(len(to_study)) if i[x] <= 10]
    # t2 = [x for x in range(len(to_study)) if (10 < i[x] and i[x] <= 20)]
    # t3 = [x for x in range(len(to_study)) if i[x] > 20]

    # plt.plot([x_axis[x] for x in t1], [np.array(to_study[x]) * 100 for x in t1], 'bo')
    # plt.plot([x_axis[x] for x in t2], [np.array(to_study[x]) * 100 for x in t2], 'rx')
    # plt.plot([x_axis[x] for x in t3], [np.array(to_study[x]) * 100 for x in t3], 'm*')
    # plt.xlabel('ASes [%]', fontsize = 16)
    # plt.ylabel('Couples (i, e) with FDs in AS [%]', fontsize = 16)
    # plt.gca().set_xlim(left=53)
    # plt.gca().set_xlim(right=101)

    # ax.set_xticks([55, 65, 75, 85, 95], minor=True)
    # # major_y_ticks = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    # # minor_y_ticks = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95]
    # major_y_ticks = 100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    # minor_y_ticks = 100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=16)
    # ax.yaxis.set_tick_params(labelsize=16)
    # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()
    # plt.savefig('percentage_couples_inc_per_AS_3colors_markers.pdf')
    # # plt.show()


    ####################################### Scatter + Text couples % in AS  #######################################
    ####################################### Scatter + Text couples % in AS  #######################################
    ####################################### Scatter + Text couples % in AS  #######################################

    # plt.figure()
    # # fig, ax = plt.subplots(1, figsize=(10, 4))
    # fig, ax = plt.subplots()
    # x_axis = 100 * np.array([x + 1 for x in range(len(to_study))]) / len(to_study)
    # plt.plot(x_axis, np.array(to_study) * 100, 'bo')

    # for j, txt in enumerate(i):
    #     if not j % 2:
    #         ax.annotate(i[j], (x_axis[j], 100 * to_study[j] + 1.5), ha='center', va='bottom', fontsize=16)
    #     else:
    #         ax.annotate(i[j], (x_axis[j], 100 * to_study[j] - 1.5), ha='center', va='top', fontsize=16)

    # plt.xlabel('ASes [%]', fontsize=16)
    # plt.ylabel('Couples (i, e) with FDs in AS [%]', fontsize=16)
    # plt.gca().set_xlim(left=53)
    # plt.gca().set_xlim(right=101)
    # plt.gca().set_ylim(top=110)
    # plt.gca().set_ylim(bottom=-10)
    # ax.set_xticks([55, 65, 75, 85, 95], minor=True)
    # # major_y_ticks = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    # # minor_y_ticks = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95]
    # major_y_ticks = 100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    # minor_y_ticks = 100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    

    # # ax.legend(loc='upper right', fancybox=True, bbox_to_anchor=(1.05, 1.05), ncol=2, shadow=True, edgecolor='k', prop={'size': 12})
    # ax.xaxis.set_tick_params(labelsize=16)
    # ax.yaxis.set_tick_params(labelsize=16)
    # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()
    # plt.savefig('percentage_couples_text.pdf')
    # # plt.show()





    # plt.figure()
    # plt.plot(q_tot, 100 * np.array([x + 1 for x in range(len(q_tot))], dtype='f') / len(q_tot))
    # plt.grid(True)
    # plt.title('CDF')
    # plt.xlabel('qPref set')
    # plt.ylabel('[%]')
    # plt.savefig('qpref_sets.pdf')
    # plt.show()  



    ####################################### Bars couples % in AS  #######################################
    ####################################### Bars couples % in AS  #######################################
    ####################################### Bars couples % in AS  #######################################


    # plt.figure()
    # fig, ax = plt.subplots(1, figsize=(10, 4))
    # x_axis = np.array([x + 1 for x in range(len(to_study))])
    # plt.bar(x_axis, np.array(to_study) * 100, color = 'b')
    # plt.xlabel('ASes [ID]', fontsize = 16)
    # plt.ylabel('Couples (i, e) with FDs in AS [%]', fontsize = 16)
    # plt.gca().set_xlim(left=30)
    # plt.gca().set_xlim(right=58)

    # major_y_ticks = 100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    # minor_y_ticks = 100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # # ax.grid(axis='x', which='both')
    # # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=16)
    # ax.yaxis.set_tick_params(labelsize=16)
    # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()
    # plt.savefig('percentage_couples_inc_per_AS_bars.pdf')




    # fig, ax = plt.subplots()
    # ax2 = ax.twinx()
    # x_axis = 100 * np.array([x + 1 for x in range(len(to_study))]) / len(to_study)
    # ax.plot(x_axis, np.array(to_study) * 100, 'bo', label = 'Couples (i, e) with FDs')
    # ax2.plot(x_axis, i, 'rx')
    # plt.xlabel('ASes [%]', fontsize = 16)
    # # plt.ylabel('Couples (i, e) with FDs in AS [%]', fontsize = 16)
    # ax.tick_params(axis='y', labelcolor='b')
    # ax2.tick_params(axis='y', labelcolor='r')
    # ax.set_ylabel("Relative [%]", fontsize = 16, color = 'b')
    # ax.yaxis.label.set_color('blue')
    # ax2.set_ylabel("Absolute [1]", fontsize = 16, color = 'r')

    # # ax.label('Relative [%]', color = 'b')

    # # ax.yaxis.label.set_color('red')
    # # ax.xaxis.label.set_color('red')
    # ax.spines['left'].set_color('blue')
    # ax2.spines['right'].set_color('red')
    # plt.gca().set_xlim(left=53)
    # plt.gca().set_xlim(right=101)

    # ax.set_xticks([55, 65, 75, 85, 95], minor=True)
    # # major_y_ticks = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    # # minor_y_ticks = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95]
    # major_y_ticks = 100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    # minor_y_ticks = 100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=16)
    # ax.yaxis.set_tick_params(labelsize=16)
    # ax2.xaxis.set_tick_params(labelsize=16)
    # ax2.yaxis.set_tick_params(labelsize=16)
    # # handles, labels = plt.gca().get_legend_handles_labels()
    # # by_label = OrderedDict(zip(labels, handles))
    # # ax.legend(loc="upper center", bbox_to_anchor=(.25, 1.15), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # # leg.get_texts()[0].set_text('Couple (i, e) with FDs')
    # # ax.legend(loc="upper center", bbox_to_anchor=(.5, 1.1), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # # ax.legend(loc="upper center", bbox_to_anchor=(.25, 1.15), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # # for item in leg.legendHandles:
    #     # item.set_visible(False)

    # # text = plt.text(0.5,1,'Couples (i, e) with FDs', transform=ax.transAxes, ha = 'center', va = 'center',
    #          # bbox=dict(facecolor='none', edgecolor='black', boxstyle='round,pad=1', alpha=None))
    # # text.set_alpha(1)
    # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()
    # plt.savefig('rel_abs_couples.pdf')
    # plt.show()


    # fig, ax = plt.subplots()
    # plt.plot(s, np.array([x + 1 for x in range(len(s_tot))], dtype='f') / len(s_tot), 'b', linewidth=1.5)
    # plt.grid(True)
    # plt.xlabel('s (# correlated sets of prefixes or routes)', fontsize = 16)
    # plt.ylabel('CDF',fontsize = 16)
    # # ax.set_xticks([10, 30, 50, 70, 90], minor=True)
    # major_y_ticks = [0, 0.2, 0.4, 0.6, 0.8, 1.0]
    # minor_y_ticks = [0.1, 0.3, 0.5, 0.7, 0.9]
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=16)
    # ax.yaxis.set_tick_params(labelsize=16)
    # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()

    


    ################################################## AS Rel Abs FDs ########################################################
    ################################################## AS Rel Abs FDs ########################################################
    ################################################## AS Rel Abs FDs ########################################################
    
    fig, ax = plt.subplots(figsize = (11, 6.25))
    ax2 = ax.twinx()
    
    x_axis = np.array([x + 1 for x in range(len(to_study))])
    pprint(x_axis)
    x_axis = [x_axis[j] for j in range(len(x_axis)) if iii[j]]


    rel_inc = [ts for ts in to_study if ts]
    inc_now = [ii for ii in iii if ii]
    asL = [ASes[j] for j in range(len(ASes))  if iii[j]]
    # ax2.bar(x_axis, inc_now, color = 'r', zorder=1)
    # ax.plot(x_axis, np.array(rel_inc) * 100, 'bx', zorder=1)
    
    ax.bar(x_axis, np.array(rel_inc) * 100, color = 'r', alpha = 0.8,
                                # hatch = hatches[n_asn % len(hatches)],
                    edgecolor='black',
                    linewidth = 1,        )
    ax2.plot(x_axis, inc_now, 'bo')
    plt.xlabel('ASes [%]', fontsize = 22)
    # plt.ylabel('Couples (i, e) with FDs in AS [%]', fontsize = 16)
    ax.tick_params(axis='y', labelcolor='r')
    ax2.tick_params(axis='y', labelcolor='b')

    ax.set_xlabel("AS number", fontsize = 22)
    ax.set_ylabel("Fraction of ASBR-couples\nsubject to FDs [%]", fontsize = 22, color = 'r')
    ax.yaxis.label.set_color('red')
    ax2.set_ylabel("ASBR-couples subject to FDs", fontsize = 22, color = 'b')


    ax.set_xticks(x_axis,minor=False)
    ax.set_xticklabels(asL,rotation=90,minor=False)
    ax.tick_params(which='major', labelsize=1)

    ax.set_ylim((0, 104))
    ax2.set_ylim((0, 52))
    # ax.label('Relative [%]', color = 'b')

    # ax.yaxis.label.set_color('red')
    # ax.xaxis.label.set_color('red')
    ax.spines['left'].set_color('red')
    ax2.spines['left'].set_color('red')
    ax.spines['right'].set_color('blue')
    ax2.spines['right'].set_color('blue')
    # plt.gca().set_xlim(left=53)
    # plt.gca().set_xlim(right=)


    # ax.set_xlim(left=29)
    # ax2.set_xlim(left=29)
    # ax.set_xlim(right=54.5)
    # ax2.set_xlim(right=54.5)
    

    # ax.set_xticks([55, 65, 75, 85, 95], minor=True)
    # major_y_ticks = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    # minor_y_ticks = [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95]
    major_y_ticks = 100 * np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    minor_y_ticks = 100 * np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    ax.set_yticks(major_y_ticks)
    ax.set_yticks(minor_y_ticks, minor=True)

    ax.set_axisbelow(True)
    # And a corresponding grid
    ax.grid(axis='y', which='both')
    ax.grid(axis='x', which='both')
    # Or if you want different settings for the grids:
    ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.tick_params(which='minor', # Options for both major and minor ticks
                    top=False, # turn off top ticks
                    left=False, # turn off left ticks
                    right=False,  # turn off right ticks
                    bottom=False) # turn off bottom ticks

    ax.xaxis.set_tick_params(labelsize=22)
    ax.yaxis.set_tick_params(labelsize=22)
    ax2.xaxis.set_tick_params(labelsize=22)
    ax2.yaxis.set_tick_params(labelsize=22)
    # handles, labels = plt.gca().get_legend_handles_labels()
    # by_label = OrderedDict(zip(labels, handles))
    # ax.legend(loc="upper center", bbox_to_anchor=(.25, 1.15), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # leg.get_texts()[0].set_text('Couple (i, e) with FDs')
    # ax.legend(loc="upper center", bbox_to_anchor=(.5, 1.1), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # ax.legend(loc="upper center", bbox_to_anchor=(.25, 1.15), fancybox=True, shadow=True, edgecolor='k', prop={'size': 16}, ncol=1)
    # for item in leg.legendHandles:
        # item.set_visible(False)

    # text = plt.text(0.5,1,'Couples (i, e) with FDs', transform=ax.transAxes, ha = 'center', va = 'center',
             # bbox=dict(facecolor='none', edgecolor='black', boxstyle='round,pad=1', alpha=None))
    # text.set_alpha(1)
    # fig.set_size_inches(6.5, 4.5)
    plt.tight_layout()
    plt.savefig('as_couples_FDs_rel_abs.pdf')
    plt.show()


    ####################################### CDF couples % in AS  #######################################
    ####################################### CDF couples % in AS  #######################################
    ####################################### CDF couples % in AS  #######################################

    # fig, ax = plt.subplots(1, figsize=(10, 4))
    # y_axis = 100 * np.array([x + 1 for x in range(len(to_study))], dtype = 'f') / len(to_study)
    # plt.plot(100 * np.array(to_study), y_axis, 'b', linewidth=2)
    # plt.xlabel("Fraction of $(i, e)$ couples exhibiting FDs [%]", fontsize = 22)
    # plt.ylabel('Number of ASes [%]', fontsize = 22)
    # # plt.gca().set_xlim(left=30)
    # # plt.gca().set_xlim(right=58)

    # ax.set_xticks([10, 30, 50, 70, 90], minor=True)
    # major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) * 100
    # minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9]) * 100
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=22)
    # ax.yaxis.set_tick_params(labelsize=22)
    # # fig.set_size_inches(6.5, 4.5)

    # plt.tight_layout()
    # plt.savefig('CDF_couples_FDs.pdf')


    ####################################### Dist S  #######################################
    ####################################### Dist S  #######################################
    ####################################### Dist S  #######################################

    s_paths = glob.glob("../nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/MDA-IP-lists/*.recovery3")
    pprint(s_paths)

    rec_data = defaultdict(dict)
    for filename in s_paths:
        with open(filename) as f:
            for line in f:
                vp, AS, i, e, ss = line.strip().split(';')
                i_e = (i, e)
                if vp not in rec_data[AS]:
                    rec_data[AS][vp] = {}
                rec_data[AS][vp][i_e] = int(ss)
                if int(ss) > 240:
                   print line, ss


    data = []
    data_rec = []
    for (AS, s_data) in s_tot:
        for vp in s_data:
            for i_e in s_data[vp]:
                data.append(s_data[vp][i_e])
                if s_data[vp][i_e] > 2:
                    print vp, AS, i_e, all_data[AS][vp][i_e]
                data_rec.append(rec_data[AS][vp][i_e])
    pprint(Counter(data))
    pprint(Counter(data_rec))
    tot = 0
    for x, y in Counter(data_rec).most_common():
        tot += y
    print('tot couples', tot)

    pprint(Counter(s))
    data = sorted(data)
    data_rec = sorted(data_rec)
    # for k,v in Counter(s).items():
    #     print v*1.0/len(s)
    fig, ax = plt.subplots(figsize=(10,5))
    plt.plot(data, np.array([x + 1 for x in range(len(data))], dtype='f') / len(data), 'r', linewidth = 2, label = '$s$ (after merging phase)')
    plt.plot(data_rec, np.array([x + 1 for x in range(len(data_rec))], dtype='f') / len(data_rec), 'b', linewidth = 2, label ='$r$ (before merging phase)')
    plt.grid(True)
    plt.xlabel('Sets composing $\mathbb{P}_X(i,e)$', fontsize = 22)
    plt.ylabel('CDF across ASBR-couples', fontsize = 22)
    major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) 
    minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9])
    ax.set_yticks(major_y_ticks)
    ax.set_yticks(minor_y_ticks, minor=True)
    # ax.set_xticks([1, 2, 3, 4 ,5 ,6 ,7 ,8 ,9, 10, 20,30,40,50,60,70,80,90, 100,200,300], minor=True)
    # ax.set_yscale('symlog')
    ax.set_xscale('log')
    # ax.minorticks_on()
    ax.set_axisbelow(True)
    # # And a corresponding grid
    ax.grid(axis='y', which='both')
    ax.grid(axis='x', which='both')
    # # Or if you want different settings for the grids:
    ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.tick_params(which='minor', # Options for both major and minor ticks
                    top=False, # turn off top ticks
                    left=False, # turn off left ticks
                    right=False,  # turn off right ticks
                    bottom=False) # turn off bottom ticks

    ax.xaxis.set_tick_params(labelsize=22)
    ax.yaxis.set_tick_params(labelsize=22)
    # fig.set_size_inches(6.5, 4.5)

    plt.legend(loc="upper right", bbox_to_anchor=(1.0, 0.5), fancybox=True, shadow=True,
           # handletextpad=0.1, columnspacing=0.2, handlelength=0.3,
           edgecolor='k', prop={'size': 20}, ncol=1)
    plt.tight_layout()
    plt.savefig('dist_s.pdf')
    plt.show()    


    ####################################### DIR  #######################################
    ####################################### DIR  #######################################
    ####################################### DIR  #######################################
    # fig, ax = plt.subplots(figsize=(10, 4))
    # plt.plot([100 * v for v in DIR_tot], np.array([x + 1 for x in range(len(DIR_tot))], dtype='f') / len(DIR_tot), 'b', linewidth = 2)
    # # ax.set_xscale('log')
    # plt.grid(True)
    # plt.xlabel('Number of prefixes correlated with the best IGP path for $(i, e)$ [%]', fontsize = 22)
    # # plt.xlabel('Number of prefixes correlated with $\mathcal{R}_X(e)$ [%]', fontsize = 22)
    # plt.ylabel('CDF', fontsize = 22)
    # major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) 
    # minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9]) 
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_yscale('log')
    # # ax.set_xscale('symlog')

    # ax.set_axisbelow(True)
    # # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=22)
    # ax.yaxis.set_tick_params(labelsize=22)
    # # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()
    # plt.savefig('qpref_with_DIR.pdf')
    # plt.show()



    fig, ax = plt.subplots(figsize=(10, 5))
    plt.plot([100 * v for v in DIR_tot], np.array([x + 1 for x in range(len(DIR_tot))], dtype='f') / len(DIR_tot), 'b', linewidth = 2)
    # plt.plot([100 * v for v in DIR_tot], np.array([x + 1 for x in range(len(DIR_tot))], dtype='f') / (0.04 *len(DIR_tot)), 'b', linewidth = 2)
    # ax.set_xscale('log')
    plt.grid(True)
    plt.xlabel('Prefixes associated to the DIR [%]', fontsize = 22)
    # plt.xlabel('Number of prefixes correlated with $\mathcal{R}_X(e)$ [%]', fontsize = 22)
    plt.ylabel('CDF across ASBR-couples', fontsize = 22)
    major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) 
    minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9]) 
    
    
    ax.set_yticks(major_y_ticks)
    ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_xscale('symlog')
    ax.set_yscale('log')
    # ax.set_xscale('symlog')

    ax.set_axisbelow(True)
    # # And a corresponding grid
    ax.grid(axis='y', which='both')
    ax.grid(axis='x', which='both')
    # # Or if you want different settings for the grids:
    ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    ax.tick_params(which='minor', # Options for both major and minor ticks
                    top=False, # turn off top ticks
                    left=False, # turn off left ticks
                    right=False,  # turn off right ticks
                    bottom=False) # turn off bottom ticks

    ax.xaxis.set_tick_params(labelsize=22)
    ax.yaxis.set_tick_params(labelsize=22)
    # fig.set_size_inches(6.5, 4.5)
    # ax.set_ylim([0, 1])
    plt.tight_layout()
    plt.savefig('qpref_with_DIR.pdf')
    plt.show()


    ####################################### INC RATE  #######################################
    ####################################### INC RATE  #######################################
    ####################################### INC RATE  #######################################

    # plt.show()
    # fig, ax = plt.subplots(figsize=(10,4))
    # plt.plot(100 * np.array(inc_rates), np.array([x + 1 for x in range(len(inc_rates))], dtype='f') / len(inc_rates), 'b', linewidth = 1.5)
    # plt.grid(True)
    # plt.xlabel('Prefixes associated with FDs [%]', fontsize = 16)
    # plt.ylabel('CDF', fontsize = 16)
    # major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) 
    # minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9]) 
    # ax.set_yticks(major_y_ticks)
    # ax.set_yticks(minor_y_ticks, minor=True)

    # ax.set_axisbelow(True)
    # # # And a corresponding grid
    # ax.grid(axis='y', which='both')
    # ax.grid(axis='x', which='both')
    # # # Or if you want different settings for the grids:
    # ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    # ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    # ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    # ax.tick_params(which='minor', # Options for both major and minor ticks
    #                 top=False, # turn off top ticks
    #                 left=False, # turn off left ticks
    #                 right=False,  # turn off right ticks
    #                 bottom=False) # turn off bottom ticks

    # ax.xaxis.set_tick_params(labelsize=16)
    # ax.yaxis.set_tick_params(labelsize=16)
    # fig.set_size_inches(6.5, 4.5)
    # plt.tight_layout()
    # plt.savefig('inc_rates.pdf')
    # plt.show()
  

# def remove_keys(data, ):



def main(input_path):
    data = read_input_files(glob.glob('/'.join([input_path, '*'])))

    # for vp in data:
    #     for AS in data[vp]:
    #         for i_e in data[vp][AS]:
    #             pprint([vp, AS, i_e, data[vp][AS][i_e]])

    # sys.exit()
    with open('couples_with_fds', 'w') as f:
        for vp in data:
            for AS in data[vp]:
                for i_e in data[vp][AS]:
                    q_prefxs = data[vp][AS][i_e] 
                    if q_prefxs[q_prefxs[-1]] < sum(q_prefxs)/1.1:
                        f.write('{vp};{AS};{ingress};{egress}\n'.format(vp=vp, AS=AS, ingress=i_e[0], egress=i_e[1]))


    print(sum([len(data[x][AS]) for x in data for AS in data[x]]))
    # sys.exit()

    # # vp_order = sorted(data.keys(), key = lambda x: len(data[x].keys()))
    # vp_order = sorted(data.keys(), key = lambda x: sum([len(data[x][AS].keys()) for AS in data[x].keys()]))[::-1]
    
    # # for vp in vp_order:
    #     # print sum([len(data[vp][AS].keys()) for AS in data[vp].keys()])

    # print len(vp_order)

    # new_order = []
    # while(len(vp_order) > 1):
    #     vp_order = sorted(vp_order, key = lambda x: sum([len(data[x][AS].keys()) for AS in data[x].keys()]))[::-1]    
    #     for i in range(1, len(vp_order)):
    #         vi = vp_order[i]
    #         for AS in data[vp_order[0]]:
    #             for i_e in data[vp_order[0]][AS]:
    #                 try:
    #                     del data[vi][AS][i_e]
    #                 except:
    #                     pass
    #     new_order.append(vp_order[0])
    #     del vp_order[0]
    # new_order.append(vp_order[0])

    # jojo = [sum([len(data[vp][AS].keys()) for AS in data[vp].keys()]) for vp in new_order]
    # pprint(sum(jojo[70:]))

    # couples = np.cumsum(jojo)
    
    # # print(max(couples))
    # # sys.exit()

    # as_list = []
    # for i in range(len(new_order) - 1):
    #     vi = new_order[i]
    #     as_list.append(len(data[vi]))
    #     for j in range(i + 1, len(new_order)):
    #         vj = new_order[j]
    #         for AS in data[vi]:
    #             try:
    #                 del data[vj][AS]
    #             except:
    #                 pass
    # as_list.append(len(data[new_order[-1]]))
    # # pprint(as_list)



    # fig, (ax, ax2) = plt.subplots(2, figsize=(10, 6), sharex=True)
    # # fig, ax = plt.subplots(figsize=(10, 4))
    # # ax2 = ax.twinx()
    # ax.plot([x for x in range(len(new_order))], couples, 'bo')
    # ax2.plot([x for x in range(len(new_order))], np.cumsum(as_list), 'ro')
    # # plt.show()

    # # major_y_ticks = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0]) 
    # # minor_y_ticks = np.array([0.1, 0.3, 0.5, 0.7, 0.9]) 
    # ax.set_xticks([x for x in range(len(new_order))][::10])

    # ax.set_yticks([1000, 2000, 3000, 4000])
    # ax.set_yticks([1500, 2500, 3500], minor=True)
    # ax.ticklabel_format(axis='y', scilimits=[-3, 3])
    # # ax2.ticklabel_format(axis='y', scilimits=[0, 3])
    # ax2.get_xaxis().get_major_formatter().set_scientific(True)
    # ax2.set_yticks([10, 20, 30, 40, 50])
    # ax2.set_yticks([15, 25, 35, 45, 55], minor=True)

    # ax.get_yaxis().set_label_coords(-0.075,0.5)
    # ax2.get_yaxis().set_label_coords(-0.075,0.5)

    # ax2.set_xlabel('Number of VPs', fontsize= 22)
    # ax.set_ylabel('ASBR-couples', fontsize= 22)
    # ax2.set_ylabel('ASes', fontsize= 22)
    # # ax.set_xticks([20, 40, 60, 80, 100], which = 'major')
    # # ax.set_xticks([10, 30, 50, 70, 90], which = 'minor')
    # # ax.set_yscale('log')
    # # ax.set_xscale('symlog')

    # # plt.xlabel('Number of Vantage Points', fontsize = 16)
    # # # plt.ylabel('Couples (i, e) with FDs in AS [%]', fontsize = 16)
    # # ax.tick_params(axis='y', labelcolor='b')
    # # ax2.tick_params(axis='y', labelcolor='r')
    # # ax.set_ylabel("Number of unique (i,e) couples", fontsize = 15, color = 'b')
    # # ax.yaxis.label.set_color('blue')
    # # ax2.set_ylabel("Number of unique ASes", fontsize = 15, color = 'r')


    # for ax in [ax, ax2]:
    #     ax.set_axisbelow(True)
    #     # # And a corresponding grid
    #     ax.grid(axis='y', which='both')
    #     ax.grid(axis='x', which='both')
    #     # # Or if you want different settings for the grids:
    #     ax.grid(axis='y', which='minor', alpha=0.5, linestyle='--', linewidth=0.5)
    #     ax.grid(axis='y', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    #     ax.grid(axis='x', which='minor', alpha=0.5, color='k', linestyle='--', linewidth=0.5)
    #     ax.grid(axis='x', which='major', alpha=1.0, color='k', linestyle='--', linewidth=0.5)
    #     ax.tick_params(which='minor', # Options for both major and minor ticks
    #                     top=False, # turn off top ticks
    #                     left=False, # turn off left ticks
    #                     right=False,  # turn off right ticks
    #                     bottom=False) # turn off bottom ticks

    #     ax.xaxis.set_tick_params(labelsize=22)
    #     ax.yaxis.set_tick_params(labelsize=22)
    #     # fig.set_size_inches(6.5, 4.5)
 
    # plt.tight_layout()
    # plt.savefig('utility.pdf')
    # plt.show()

    # sys.exit()





    data = reindex_by_AS(data)
    # pprint(len(data.keys()))
    genearte_plots(data)





if __name__ == "__main__":
    input_path = "../nlnog-ring-stuff/LARGE-SCALE-2020/results-20200524/pre_results"
    main(input_path)


