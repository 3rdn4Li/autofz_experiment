import os
import argparse
from loguru import logger
from typing import List
import sys
import tarfile
import subprocess
import shutil
import statistics
import numpy as np
import seaborn as sns
from matplotlib import colors
from matplotlib import pyplot as plt
import pandas as pd



supported_targets=["freetype2-2017","harfbuzz-1.3.2","lcms-2017-03-21","libjpeg-turbo-07-2017","libpng-1.2.56","libxml2-v2.9.2","openssl-1.0.1f","vorbis-2017-12-11","woff2-2016-05-06",\
                    "openssl-1.0.2d","proj4-2017-08-14","re2-2014-12-09","sqlite-2016-11-14","openssl-1.1.0c-bignum"]
supported_targets+=["openssl-1.1.0c-x509","openthread-2018-02-27-radio","openthread-2018-02-27-ip6","boringssl-2016-02-12","libarchive-2017-01-04","wpantund-2018-02-27","json-2017-02-12","guetzli-2017-3-30"]
supported_targets+=["libssh-2017-1272","c-ares-CVE-2016-5180","pcre2-10.00"]

supported_fuzzers=["afl","aflfast","redqueen","lafintel","fairfuzz","mopt","radamsa","angora"]#,"qsym","learnafl","libfuzzer"]

def main():
    parser=argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest=argparse.SUPPRESS, required=True)

    parser_launch=subparsers.add_parser("launch", help="Launch experiment")
    parser_launch.add_argument("-e","--experiment_name", required=True,help="Experiment name")
    parser_launch.add_argument("-t","--fuzz_target", nargs="+", choices=supported_targets, default=supported_targets, help="Fuzz targets")
    parser_launch.add_argument("-fz","--fuzzer", nargs="+", choices=supported_fuzzers, default=supported_fuzzers, help="Fuzzer")
    parser_launch.add_argument("-tn","--trail_number", type=int, default=3, help="Trail number")
    parser_launch.add_argument("-j","--cpu_number", type=int, default=1, help="Total CPU number for each trail")
    parser_launch.set_defaults(func=launch)

    # parser_ppfb=subparsers.add_parser("pp_fb", help="Prepare directory for fuzzbench, directory structure is fuzz_target/fuzzer/trail")
    # parser_ppfb.add_argument("-d","--experiment_directory", required=True,help="Experiment directory")
    # parser_ppfb.add_argument("-df","--data_folder",  help="Folder to store data for computing coverage")
    # parser_ppfb.set_defaults(func=pp_fb)   

    parser_ppautofz=subparsers.add_parser("pp_autofz", help="Prepare directory for autofz, directory structure is fuzz_target/fuzzer/trail")
    parser_ppautofz.add_argument("-d","--experiment_directory", required=True,help="Experiment directory")
    parser_ppautofz.add_argument("-tm","--timeover", type=int, required=True, help="Fuzzing campaign time in hours used to delete time over seeds")
    parser_ppautofz.add_argument("-df","--data_folder",  help="Folder to store data for computing coverage")
    parser_ppautofz.set_defaults(func=pp_autofz) 

    parser_coverage=subparsers.add_parser("coverage", help="Compute coverage")
    parser_coverage.add_argument("-df","--data_folder", required=True,   help="Folder storing data for computing coverage")
    parser_coverage.add_argument("-tm","--timeover", type=int, required=True, help="Fuzzing campaign time in hours used to delete time over seeds")
    parser_coverage.add_argument("-cf","--coverage_folder", required=True, help="Folder containing coverage binaries")
    parser_coverage.set_defaults(func=coverage)  

    parser_report=subparsers.add_parser("report", help="Generate experiment report")
    parser_report.add_argument("-df","--data_folder", required=True,help="Folder storing data for computing coverage")
    parser_report.add_argument("-cf","--coverage_folder", required=True, help="Folder containing coverage binaries")
    parser_report.add_argument("-tm","--timeover", type=int, required=True, help="Fuzzing campaign time in hours used to delete time over seeds")
    parser_report.set_defaults(func=report)

    parser_plot=subparsers.add_parser("plot", help="Generate coverage plots")
    parser_plot.add_argument("-df","--data_folder", required=True,help="Folder storing data for computing coverage")
    parser_plot.add_argument("-cf","--coverage_folder", required=True, help="Folder containing coverage binaries")
    parser_plot.add_argument("-tm","--timeover", type=int, required=True, help="Fuzzing campaign time in hours used to delete time over seeds")
    parser_plot.set_defaults(func=plot)

    parser_source_cov=subparsers.add_parser("source_cov", help="Generate source-based code coverage, source code required")
    parser_source_cov.add_argument("-df","--data_folder", required=True,help="Folder storing data for computing coverage")
    parser_source_cov.add_argument("-cf","--coverage_folder", required=True, help="Folder containing coverage binaries")
    parser_source_cov.set_defaults(func=source_cov)

    parser_sieve=subparsers.add_parser("sieve", help="Find the first seed that covers a specific line in a specific file, source code required")
    parser_sieve.add_argument("-tf","--trail_folder", required=True,help="Trail folder containing seeds")
    parser_sieve.add_argument("-cb","--coverage_binary", required=True, help="Coverage binary")
    parser_sieve.add_argument("-f","--file_name", required=True, help="The file you want to cover")
    parser_sieve.add_argument("-l","--line", required=True, help="The line you want to cover")
    parser_sieve.set_defaults(func=sieve)     
    
    args=parser.parse_args()
    dict_args = vars(args)
    if("fuzz_target" in dict_args):
        dict_args["fuzz_target"]=list(set(args.fuzz_target))
    func = dict_args.pop("func")
    func(**dict_args)



def launch(experiment_name: str, fuzzer: List[str], fuzz_target: List[str],trail_number:int, cpu_number:int):
    #fuzz_target=[supported_targets_to_full[fz] for fz in fuzz_target]
    logger.info(f"Launching experiment {experiment_name}")
    logger.info(f"Fuzzers: {fuzzer}")
    try_makedirs(experiment_name)
    logger.info(f"Fuzz targets: {fuzz_target}")
    if trail_number<=0:
        error_exit("Trail num should be greater than 0.")
    current_directory = os.getcwd()
    for trail in range(trail_number):
        for fz_target in fuzz_target:
            trail_name=fz_target+"_8_trail_"+str(trail)
            trail_folder=os.path.join(experiment_name,trail_name)
            os.makedirs(trail_folder)
            os.chdir(trail_folder)
            print(cpu_number)
            if cpu_number<=0:
                error_exit("CPU number should be greater than 0.")
            elif cpu_number==1:
                logger.info("Using one cpu")
                cmd_launch= f"docker run --rm --name {trail_name} --cpus=1 -d --privileged -v $PWD:/work/autofz -w /work/autofz \
-it autofz /bin/bash -c \"sudo /init.sh && autofz -o output -T 24h -f {' '.join(map(str, fuzzer))} -t {fz_target}\""
            else:
                logger.info(f"Using {cpu_number} cpus")
                cmd_launch= f"docker run --rm  --name {trail_name} --cpus={cpu_number} -d --privileged -v $PWD:/work/autofz -w /work/autofz \
-it autofz /bin/bash -c \"sudo /init.sh && autofz -o output -T 24h -f {' '.join(map(str, fuzzer))} -j{cpu_number} -p -t {fz_target}\""
            logger.info(cmd_launch)
            os.system(cmd_launch)
            os.chdir(current_directory)
  

# def pp_fb(experiment_directory: str, data_folder:str):
#     experiment_name=os.path.basename(experiment_directory)
#     if not data_folder:
#         data_folder=os.path.normpath(experiment_name)+"_data"
#     logger.info(f"Coverage_folder: {data_folder}")
#     try_makedirs(data_folder)
#     experiment_directory=os.path.abspath(experiment_directory)
#     fuzzbench_experiment_folders=os.path.join(experiment_directory,"experiment-folders")
#     target_fuzzer_folder = [d for d in os.listdir(fuzzbench_experiment_folders) if os.path.isdir(os.path.join(fuzzbench_experiment_folders, d))]
#     targets=list(set([s.split("_")[0] for s in target_fuzzer_folder]))
#     fuzzers=list(set([s.split("-")[-1] for s in target_fuzzer_folder]))
#     for tg in targets:
#         for fz in fuzzers:
#             try_makedirs(os.path.join(data_folder,tg,fz))
#     for t_t_f in target_fuzzer_folder:
#         now_target=t_t_f.split("_")[0]
#         now_fuzzer=t_t_f.split("-")[-1]
#         now_data_folder=os.path.join(data_folder,now_target,now_fuzzer)
#         trail_folder = [d for d in os.listdir(os.path.join(fuzzbench_experiment_folders,t_t_f)) if os.path.isdir(os.path.join(os.path.join(fuzzbench_experiment_folders,t_t_f), d))]
#         for t_f in trail_folder:
#             now_trail=os.path.join(now_data_folder,t_f)
#             try_makedirs(now_trail)
#             logger.info(f"extracting {os.path.join(fuzzbench_experiment_folders,t_t_f,t_f)}")
#             extract_seeds(os.path.join(fuzzbench_experiment_folders,t_t_f,t_f,"corpus"),os.path.abspath(now_trail))


def pp_autofz(experiment_directory: str, data_folder:str,timeover:int):
    if timeover<=0:
        error_exit("Timeover should be greater than 0.")
    experiment_name=os.path.basename(experiment_directory)
    if not data_folder:
        data_folder=os.path.normpath(experiment_name)+"_data"
    logger.info(f"Coverage_folder: {data_folder}")
    try_makedirs(data_folder)
    experiment_directory=os.path.abspath(experiment_directory)
    target_trail_folders = [d for d in os.listdir(experiment_directory) if os.path.isdir(os.path.join(experiment_directory, d))]
    targets=list(set([s.split("_")[0] for s in target_trail_folders]))
    fuzzers=["autofz"]
    trail=list(set([s.split("trail")[-1] for s in target_trail_folders]))
    for tg in targets:
        for fz in fuzzers:
            try_makedirs(os.path.join(data_folder,tg,fz))
    for t_t_f in target_trail_folders:
        now_target=t_t_f.split("_")[0]
        now_trail=t_t_f.split("trail")[-1]
        dst_traget_trail=os.path.join(data_folder,now_target,fz,now_trail)
        try_makedirs(dst_traget_trail)
        for time_span in range(0,timeover*60+1,15):
            dir_span=os.path.join(dst_traget_trail,str(time_span))
            try_makedirs(dir_span)
        try_makedirs(os.path.join(dst_traget_trail,"timeout"))
        src_output_dir=os.path.join(experiment_directory,t_t_f,"output",t_t_f.split("_")[0])
        for fuzzer_output in os.listdir(src_output_dir):
            if not os.path.isdir(os.path.join(src_output_dir,fuzzer_output)):
                continue
            for fuzzer_instance_output in os.listdir(os.path.join(src_output_dir,fuzzer_output)):
                if (not os.path.isdir(os.path.join(src_output_dir,fuzzer_output,fuzzer_instance_output)))or(fuzzer_instance_output=="autofz"):
                    continue
                for look_for_queue in os.listdir(os.path.join(src_output_dir,fuzzer_output,fuzzer_instance_output)):
                    if look_for_queue=="queue" and os.path.isdir(os.path.join(src_output_dir,fuzzer_output,fuzzer_instance_output,"queue")):
                        logger.info(f"copying seeds from {os.path.join(src_output_dir,fuzzer_output,fuzzer_instance_output)}")
                        copy_seeds(os.path.join(src_output_dir,fuzzer_output,fuzzer_instance_output,"queue"),dst_traget_trail,timeover)



    
    
    


    
    #copy_seeds(experiment_directory,data_folder,timeover)

def coverage(data_folder:str,coverage_folder:str,timeover:int):
    data_folder=os.path.abspath(data_folder)
    coverage_folder=os.path.abspath(coverage_folder)
    for target_d in os.listdir(data_folder):
        if target_d not in supported_targets:
            continue
        target_dir=os.path.join(data_folder, target_d)
        if not os.path.isdir(target_dir):
            continue
        for fuzzer_d in os.listdir(target_dir):
            target_fuzzer_dir=os.path.join(target_dir, fuzzer_d)
            if not os.path.isdir(target_fuzzer_dir):
                continue
            for trail_d in os.listdir(target_fuzzer_dir):
                target_fuzzer_trail_dir=os.path.join(target_fuzzer_dir, trail_d)
                if not os.path.isdir(target_fuzzer_trail_dir):
                    continue
                current_directory = os.getcwd()
                time_spans=[]
                for time_span in range(0,timeover*60+1,15):
                    time_spans.append(time_span)
                    target_fuzzer_trail_span_dir=os.path.join(target_fuzzer_trail_dir,str(time_span))
                    os.chdir(target_fuzzer_trail_span_dir)
                    os.system("rm -rf *.prof*")
                    coverage_binary_list=os.listdir(os.path.join(coverage_folder,target_d))
                    if len(coverage_binary_list)>1:
                            error_exit(f"{os.path.join(coverage_folder,target_d)} has more than one binary, there should be only one!")
                    coverage_binary=os.path.join(coverage_folder,target_d,coverage_binary_list[0])

                    if time_span==0:
                        logger.info(f"coverage_binary is {coverage_binary}")
                        logger.info(f"running coverage binary using seeds of {target_fuzzer_trail_dir}")
                    
                    seed_all=[]
                    for seed in os.listdir(target_fuzzer_trail_span_dir):
                        if not seed.startswith("id:"):
                            continue
                        seed_abs=os.path.join(target_fuzzer_trail_span_dir,seed)
                        if os.path.isfile(seed_abs):
                            seed_all.append(seed)
                    
                    #in linux, the length of args are restricted
                    if(len(seed_all)<=100):
                        run_coverage_cmd=[coverage_binary]
                        run_coverage_cmd+=seed_all
                        process=subprocess.Popen(run_coverage_cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                        try:
                            process.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            logger.error(f"timeout")
                            for seed in seed_all:
                                run_coverage_cmd=[coverage_binary,seed]
                                process=subprocess.Popen(run_coverage_cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                                try:
                                    process.wait(timeout=30)
                                except subprocess.TimeoutExpired:
                                    logger.error(f"timeout seed {seed}")
                                    try_copy(seed,"../timeout")
                                    
                    else:
                        for i in range(0,len(seed_all),100):
                            llvm_env={
                                "LLVM_PROFILE_FILE":f"{i}.profraw"
                            }
                            run_coverage_cmd=[coverage_binary]
                            run_coverage_cmd+=seed_all[i:min(i+100,len(seed_all))]
                            process=subprocess.Popen(run_coverage_cmd,stdout=subprocess.DEVNULL,env=llvm_env,stderr=subprocess.DEVNULL)
                            try:
                                process.wait(timeout=30)
                            except subprocess.TimeoutExpired:
                                logger.error(f"timeout")
                                for seed in seed_all[i:min(i+100,len(seed_all))]:
                                    run_coverage_cmd=[coverage_binary,seed]
                                    process=subprocess.Popen(run_coverage_cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                                    try:
                                        process.wait(timeout=30)
                                    except subprocess.TimeoutExpired:
                                        logger.error(f"timeout seed {seed}")
                                        try_copy(seed,"../timeout")
                            #logger.info(f"done {min(i+100,len(seed_all))} seeds.")
                    merge_cmd="llvm-profdata merge -sparse "
                    for span_dir in time_spans:
                        merge_cmd+=f"../{span_dir}/*.profraw "
                    merge_cmd+="-o default.profdata"
                    #print(merge_cmd)
                    os.system(merge_cmd)
                    assert(os.path.exists("default.profdata"))
                os.chdir(current_directory)




def plot(data_folder: str,coverage_folder:str, timeover:int):
    current_directory = os.getcwd()
    data_folder=os.path.abspath(data_folder)
    coverage_folder=os.path.abspath(coverage_folder)
    for target_d in os.listdir(data_folder):
        if target_d not in supported_targets:
            continue
        target_dir=os.path.join(data_folder, target_d)
        if not os.path.isdir(target_dir):
            continue
        for fuzzer_d in os.listdir(target_dir):
            target_fuzzer_dir=os.path.join(target_dir, fuzzer_d)
            if not os.path.isdir(target_fuzzer_dir):
                continue
            branches=[]
            for trail_d in os.listdir(target_fuzzer_dir):
                target_fuzzer_trail_dir=os.path.join(target_fuzzer_dir, trail_d)
                if not os.path.isdir(target_fuzzer_trail_dir):
                    continue
                time_max=int(timeover*60//15*15)
                for timespan in range(0,time_max+1,15):
                    timespan_dir=os.path.join(target_fuzzer_trail_dir,str(timespan))
                    os.chdir(timespan_dir)
                    coverage_binary_list=os.listdir(os.path.join(coverage_folder,target_d))
                    if len(coverage_binary_list)>1:
                            error_exit(f"{os.path.join(coverage_folder,target_d)} has more than one binary, there should be only one!")
                    coverage_binary=os.path.abspath(os.path.join(coverage_folder,target_d,coverage_binary_list[0]))
                    #logger.info(f"target: {target_d}, trail: {trail_d}, fuzzer: {fuzzer_d}")
                    #llvm-cov report -instr-profile=default.profdata {coverage_binary}
                    output = subprocess.check_output(f"llvm-cov report -instr-profile=default.profdata {coverage_binary} | grep TOTAL",text=True, shell=True)
                    # region=int(output.split()[1])-int(output.split()[2])
                    # regions.append(region)
                    # function=int(output.split()[4])-int(output.split()[5])
                    # functions.append(function)
                    # line=int(output.split()[7])-int(output.split()[8])
                    # lines.append(line)
                    branch=int(output.split()[10])-int(output.split()[11])
                    branches.append(branch)
            os.chdir(current_directory)
            trail_num=len(os.listdir(target_fuzzer_dir))
            times=[i for i in range(0,timeover*60*60+1,15*60)]*trail_num
            # print(branches)
            # print(times)
            data={'branches': branches,'times': times}
            df = pd.DataFrame(data)


            _DEFAULT_TICKS_COUNT = 12
            width = 6.4
            height = 4.8
            figsize = (2 * width, height) 
            fig, axs = plt.subplots(figsize=figsize)
            axes = sns.lineplot(
                y='branches',
                x='times',
                data=df,
                ci= 95,
                estimator=np.median,
                #style='fuzzer',
                marker='o',
                dashes=False,
                ax=axs)

            axes.set_title(f"{target_d}_{coverage_binary_list[0]} ({timeover}h, at least {trail_num} trails/fuzzer)")

            # Indicate the snapshot time with a big red vertical line.
            axes.axvline(x=timeover*60*60, color='r')

            # Move legend outside of the plot.
            axes.legend(bbox_to_anchor=(1.00, 1),
                        borderaxespad=0,
                        loc='upper left',
                        frameon=False)

            axes.set(ylabel= 'Code branch coverage')
            axes.set(xlabel='Time (hour:minute)')
            ticks = np.arange(
                    0.0,
                    timeover*60*60 + 1,  # Include tick at end time.
                    max(timeover*60*60 / _DEFAULT_TICKS_COUNT, 1))

            axes.set_xticks(ticks)
            axes.set_xticklabels([formatted_hour_min(t) for t in ticks])

            plt.xlim(0)
            sns.despine(ax=axes, trim=True)
            #print(f"{target_d}_{coverage_binary_list[0]}.png")
            fig.savefig(f"{target_d}_{coverage_binary_list[0]}.png", bbox_inches='tight')
            plt.close(fig)
                
            

def formatted_hour_min(seconds):
    """Turns |seconds| seconds into %H:%m format.

    We don't use to_datetime() or to_timedelta(), because we want to
    show hours larger than 23, e.g.: 24h:00m.
    """
    time_string = ''
    hours = int(seconds / 60 / 60)
    minutes = int(seconds / 60) % 60
    if hours:
        time_string += f'{hours}h'
    if minutes:
        if hours:
            time_string += ':'
        time_string += f'{minutes}m'
    if seconds == 0:
        time_string = '0m'
    return time_string

def report(data_folder: str,coverage_folder:str, timeover:int):
    data_folder=os.path.abspath(data_folder)
    coverage_folder=os.path.abspath(coverage_folder)
    for target_d in os.listdir(data_folder):
        if target_d not in supported_targets:
            continue
        target_dir=os.path.join(data_folder, target_d)
        if not os.path.isdir(target_dir):
            continue
        for fuzzer_d in os.listdir(target_dir):
            target_fuzzer_dir=os.path.join(target_dir, fuzzer_d)
            if not os.path.isdir(target_fuzzer_dir):
                continue
            regions=[]
            functions=[]
            lines=[]
            branches=[]
            for trail_d in os.listdir(target_fuzzer_dir):
                target_fuzzer_trail_dir=os.path.join(target_fuzzer_dir, trail_d)
                if not os.path.isdir(target_fuzzer_trail_dir):
                    continue
                current_directory = os.getcwd()
                timespan=int(timeover*60//15*15)
                #print(timespan)
                timespan_dir=os.path.join(target_fuzzer_trail_dir,str(timespan))
                os.chdir(timespan_dir)
                #print(os.getcwd())
                coverage_binary_list=os.listdir(os.path.join(coverage_folder,target_d))
                if len(coverage_binary_list)>1:
                        error_exit(f"{os.path.join(coverage_folder,target_d)} has more than one binary, there should be only one!")
                coverage_binary=os.path.abspath(os.path.join(coverage_folder,target_d,coverage_binary_list[0]))
                #logger.info(f"target: {target_d}, trail: {trail_d}, fuzzer: {fuzzer_d}")
                #llvm-cov report -instr-profile=default.profdata {coverage_binary}
                output = subprocess.check_output(f"llvm-cov report -instr-profile=default.profdata {coverage_binary} | grep TOTAL",text=True, shell=True)
                region=int(output.split()[1])-int(output.split()[2])
                regions.append(region)
                function=int(output.split()[4])-int(output.split()[5])
                functions.append(function)
                line=int(output.split()[7])-int(output.split()[8])
                lines.append(line)
                branch=int(output.split()[10])-int(output.split()[11])
                branches.append(branch)
                os.chdir(current_directory)
            print(f"target:{target_d}, fuzzer:{fuzzer_d}")
            print(f"reg mean: {statistics.mean(regions)} reg std: {statistics.stdev(regions)} func mean: {statistics.mean(functions)} func std: {statistics.stdev(functions)}\
 line mean: {statistics.mean(lines)} line std: {statistics.stdev(lines)} branch mean: {statistics.mean(branches)} branch std: {statistics.stdev(branches)}")

def source_cov(data_folder: str,coverage_folder:str):
    if not os.path.exists("source_cov"):
        try_makedirs("source_cov")
    data_folder=os.path.abspath(data_folder)
    coverage_folder=os.path.abspath(coverage_folder)
    for target_d in os.listdir(data_folder):
        if target_d not in supported_targets:
            continue
        target_dir=os.path.join(data_folder, target_d)
        if not os.path.isdir(target_dir):
            continue
        for fuzzer_d in os.listdir(target_dir):
            target_fuzzer_dir=os.path.join(target_dir, fuzzer_d)
            if not os.path.isdir(target_fuzzer_dir):
                continue
            for trail_d in os.listdir(target_fuzzer_dir):
                target_fuzzer_trail_dir=os.path.join(target_fuzzer_dir, trail_d)
                if not os.path.isdir(target_fuzzer_trail_dir):
                    continue
                current_directory = os.getcwd()
                os.chdir(target_fuzzer_trail_dir)
                coverage_binary_list=os.listdir(os.path.join(coverage_folder,target_d))
                if len(coverage_binary_list)>1:
                        error_exit(f"{os.path.join(coverage_folder,target_d)} has more than one binary, there should be only one!")
                coverage_binary=os.path.abspath(os.path.join(coverage_folder,target_d,coverage_binary_list[0]))
                logger.info(f"target: {target_d}, trail: {trail_d}, fuzzer: {fuzzer_d}")
                target_fuzzer_trail_dir=os.path.abspath(target_fuzzer_trail_dir)
                sourcecov_file=os.path.join(current_directory,"source_cov",f'{target_d}_{fuzzer_d}_{trail_d}_sourcecov')
                subprocess.check_output(f"llvm-cov show -instr-profile=default.profdata {coverage_binary} > {sourcecov_file}",text=True, shell=True)
                os.chdir(current_directory)

def sieve(trail_folder: str,coverage_binary:str, file_name:str, line:str):
    if os.path.exists("sieve_tmp"):
        try_rmdirs("sieve_tmp")
    try_makedirs("sieve_tmp")
    sieve_tmp=os.path.abspath("sieve_tmp")
    trail_folder=os.path.abspath(trail_folder)
    coverage_binary=os.path.abspath(coverage_binary)
    current_directory = os.getcwd()
    os.chdir(sieve_tmp)
    seeds=[sd for sd in os.listdir(trail_folder) if sd.startswith("id:")]
    i=0
    for seed in sorted(seeds, key=lambda s: float(s[-12:])):
        if (not os.path.isdir(os.path.join(trail_folder,seed))):
            i+=1
            if i%100==0:
                logger.info(f"{i} seeds proceeded")
            os.system("rm -rf *.prof*")
            run_coverage_cmd=[coverage_binary,os.path.join(trail_folder,seed)]
            process=subprocess.Popen(run_coverage_cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            process.wait()
            os.system("llvm-profdata merge -sparse *.profraw -o default.profdata")
            assert(os.path.exists("default.profdata"))
            output=subprocess.check_output(f"llvm-cov show -instr-profile=default.profdata {coverage_binary}",text=True, shell=True)
            after_file=output.split(file_name)[1]
            after_line=after_file.split(line)[1]
            hit_num=int(after_line.split("|")[1])
            if hit_num>0:
                print(seed)
                with open("cov"+os.path.basename(seed), "w") as file:
                    file.write(output)
                try_copy(os.path.join(trail_folder,seed),".")
                break
    os.chdir(current_directory)  



        
      



def extract_seeds(src:str, dst:str):
    for filename in os.listdir(src):
        if filename.endswith('.tar.gz'):
            source_file = os.path.join(src, filename)
            with tarfile.open(source_file, 'r:gz') as tar:
                tar.extractall(dst)
    seeds=sorted([seed for seed in os.listdir(dst) if seed.startswith("id:")])
    start_time=os.path.getmtime(os.path.join(dst,seeds[0]))
    for seed in seeds:
        mod_time=f"{os.path.getmtime(os.path.join(dst,seed))-start_time:.12f}"[:12]
        try_rename(os.path.join(dst,seed),os.path.join(dst,seed+"_"+f"{mod_time}"))

def copy_seeds(src:str, dst:str,timeover:int):
    fuzz_name=src.split("/")[-3]
    seeds=[seed for seed in os.listdir(src) if seed.startswith("id:")]
    if len(seeds)==0:
        return
    start_time=os.path.getmtime(os.path.join(src,seeds[0]))
    seeds=[seed for seed in seeds if (os.path.getmtime(os.path.join(src,seed))-start_time<=timeover*60*60)]
    for time_span in range(0,timeover*60+1,15):
        dir_span=os.path.join(dst,str(time_span))
        if time_span==0:
            seeds_in_span=[seed for seed in seeds if ("orig:" in seed)]
        else:
            seeds_in_span=[seed for seed in seeds if ( (os.path.getmtime(os.path.join(src,seed))-start_time<=time_span*60) and (os.path.getmtime(os.path.join(src,seed))-start_time>(time_span-15)*60))]
        for seed in seeds_in_span:
            mod_time=f"{os.path.getmtime(os.path.join(src,seed))-start_time:.12f}"[:12]
            try_copy(os.path.join(src,seed),os.path.join(dir_span,seed+"_"+fuzz_name+"_"+f"{mod_time}"))
        

def try_makedirs(dir:str):
    try:
        os.makedirs(dir)
    except Exception as e:
        error_exit(e)

def try_rmdirs(dir:str):
    try:
        shutil.rmtree(dir)
    except Exception as e:
        error_exit(e)

def try_copy(src:str,dir:str):
    try:
        shutil.copy(src,dir)
    except Exception as e:
        error_exit(e)
def try_rename(src:str,dir:str):
    try:
        os.rename(src, dir)
    except Exception as e:
        error_exit(e)

def error_exit(emessage):
    logger.error(emessage)
    sys.exit()

if __name__=="__main__":
    main()

