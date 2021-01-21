"""
Distribution plot options
=========================

"""
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
#from matplotlib.ticker import MultipleLocator
from statsmodels.distributions.empirical_distribution import ECDF
from matplotlib.ticker import MultipleLocator, FormatStrFormatter
from cycler import cycler

def plotECDF(data, ax, xlabel=None, label=None, survival=None, color=None, linestyle="solid", xscale="lin", yscale="lin", xlim=None, ylim=(0,1), majorxTicks=None, extendLeft=0, savefig=None, format="pdf"):

#    if color == None:
#        #plt.rc('lines', linewidth=4)
#        plt.rc('axes', prop_cycle=(cycler('color', ['r', 'g', 'b', 'y', 'k', 'm'])))
            
#            +cycler('linestyle', ['-', '--', ':', '-.'])))

    data = list(data)
    data.sort()
    ecdf = ECDF(data)
    y = ecdf(data) if not survival else 1-ecdf(data)
    y = list(y)
#    print len(data)
#    print len(y)
#    if addZeroZero:
#        data.insert(0, 0)
#        y = list(y)
#        y.insert(0, 0)
#
#    print len(data)
#    print len(y)
    if extendLeft != None:
        data.insert(0, extendLeft) # value (with null probability)
        if not survival:
            y.insert(0, 0.0)  # probability
        else:
            y.insert(0, 1.0) # probability (CCDF)

    if color == None:
        ax.step(data, y, label=label, linestyle=linestyle, where="post")
    else:
        ax.step(data, y, label=label, color=color, linestyle=linestyle, where="post")
#ax.plot(data, y, label=label, color=color, linestyle=linestyle)
    ylabel = "CDF" if not survival else "CCDF"
    if ylabel:
        ax.set_ylabel(ylabel)
    if xlabel:
        ax.set_xlabel(xlabel)
    
    if xscale == "log":
        ax.set_xscale("log")
        #ax.set_xticks([i*10**exp for exp in range(-4, 2) for i in range(1, 10)], minor=True)
        #ax.set_xticks([10**exp for exp in range(-4, 3) ], minor=False)

    if yscale == "log":
        ax.set_yscale("log")
        #ax.set_yticks([i*10**exp for exp in range(-1, 9) for i in range(1, 1)], minor=True)

    if majorxTicks:
        ax.set_xticks(majorxTicks, minor=False)


#    ax.tick_params(axis='x',which='minor',top='off')
#    ax.tick_params(axis='x',which='major',top='off')
#    ax.tick_params(axis='y',which='major',right='off')
#    ax.tick_params(axis='y',which='minor',right='off')
    ax.tick_params(axis='x',which='minor',top=False)
    ax.tick_params(axis='x',which='major',top=False)
    ax.tick_params(axis='y',which='major',right=False)
    ax.tick_params(axis='y',which='minor',right=False)
    
    majorFormatter = FormatStrFormatter('%g')
#    majorFormatter = FormatStrFormatter('%.2f')
    ax.xaxis.set_major_formatter(majorFormatter)
    ax.yaxis.set_major_formatter(majorFormatter)

    if xlim:
        ax.set(xlim=xlim)
    else:
        ax.set( xlim=(min(data), max(data)) )

    if ylim:
        ax.set(ylim=ylim)


#    ax.set(xlim=xlim) 
    legend = ax.legend(loc='lower right') if not survival else ax.legend(loc="upper right")

    if savefig:
        plt.savefig(savefig, format=format)

def dropNull(x):
    return x[x.notnull()]


if __name__ == "__main__":

    # USE TEX (occhio alle label!)
    plt.rc('text', usetex=True)
    plt.rc('font', family='serif')
    
    
    sns.set_style({'font.family':'serif', 'font.serif':'Computer Modern'})
    sns.set_context("paper", font_scale=20, rc={"lines.linewidth": 4.0})
    sns.set(style="ticks", palette="muted", color_codes=True )
    sns.set_style("ticks",
                    {
                    "xtick.direction": "in",
                    "ytick.direction": "in",
                    "ytick.major.size": 4,
                    "ytics.minor.size": 2,
                    "xticks.major.size": 4,
                    "xtick.minor.size": 4
                    }
                    )
    
    # Set up the matplotlib figure
    #f, axes = plt.subplots(4, 3, figsize=(15, 15), sharex=True)
    
    
    #sns.despine(left=True)
    #sns.despine( offset=10)
    
    dataAWS = pd.read_csv('AWSerror_stats.csv', delimiter="\t")
    #.sort_values("HTTPGET1:80", ascending=False)
    dataAZURE = pd.read_csv('AZUREerror_stats.csv', delimiter="\t")
    #.sort_values("HTTPGET1:80", ascending=False)
    
    
    icmpAWS = dropNull(dataAWS["ICMP:None_cons"])
    tcp80AWS = dropNull(dataAWS["TCPSYN:80_cons"])
    tcp54321AWS = dropNull(dataAWS["TCPSYN:54321_cons"])
    http80AWS = dropNull(dataAWS["HTTPGET1:80_cons"])
    http54321AWS = dropNull(dataAWS["HTTPGET1:54321_cons"])
    http2AWS = dropNull(dataAWS["HTTPGET2:54321_cons"])
    
    tcp80AZURE = dropNull(dataAZURE["TCPSYN:80_cons"])
    tcp54321AZURE = dropNull(dataAZURE["TCPSYN:54321_cons"])
    http80AZURE = dropNull(dataAZURE["HTTPGET1:80_cons"])
    http54321AZURE = dropNull(dataAZURE["HTTPGET1:54321_cons"])
    http2AZURE = dropNull(dataAZURE["HTTPGET2:54321_cons"])
    
    
    
    COLS = 2
    ROWS = 4
    f, axes = plt.subplots(ROWS, COLS, figsize=(7, 12))
    counter = 0
    for surv in [False, True]:
        for xsc in ["lin", "log"]:
            for ysc in ["lin", "log"]:
    
                col = counter % COLS
                row = counter / COLS
                plotECDF(tcp80AWS, axes[row,col], label="AAA", xlabel="xaxis",  xscale=xsc, yscale=ysc, survival=surv, xlim=(0, 1))
                plotECDF(tcp80AZURE, axes[row,col], label="BBB", xlabel="xaxis", xscale=xsc, yscale=ysc, color="b", survival=surv, xlim=(0, 1))
                counter += 1
    
    
    
    #plt.setp(axes, yticks=[])
    #plt.setp(axes)
    #for r in range(1, ROWS):
    #    for c in range(1, COLS):
    #        axes[r, c].set_yticks(np.arange(0,1.1,0.2))
    #        axes[r, c].set_yticks(np.arange(0,1.1,0.1), minor=True)
    #        axes[r, c].set_xticks(np.arange(0,1.1,0.2))
    #        axes[r, c].set_xticks(np.arange(0,1.1,0.1), minor=True)
    #        axes[r, c].tick_params(axis='x',which='minor',top='off')
    #        axes[r, c].tick_params(axis='x',which='major',top='off')
    #        axes[r, c].tick_params(axis='y',which='major',right='off')
    #        axes[r, c].tick_params(axis='y',which='minor',right='off')
    #        axes[r, c].set_ylabel("CDF")
    #        axes[r, c].set_xlabel('Error Rate')
    #        axes[r,c].set(xlim=(0,1))
    
    
    #sns.plt.savefig("analisi1_merged.pdf", format="pdf")
    plt.tight_layout()
    sns.plt.show()
