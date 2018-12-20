#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import angr
import argparse
import os
from angrutils import *
import multiprocessing as mp
import pymongo

# 数据库链接URL
DBURL = "mongodb://10.10.2.192:27017/"
# 数据库名
DB = "feature"
# 集合名
COL = "bin"


def in_ins_list(instruction, ins_list):
    """
    判断当前指令是否在指令列表中
    :param instruction:
    :param ins_list:
    :return:
    """
    up_ins = instruction.upper()
    for ins in ins_list:
        if ins in up_ins:
            return True
    return False


def handle_ins(insns):
    """
    统计基本块中指令类型的数量
    :param insns:
    :return:
    """
    transfer_ins = ['MOV', 'PUSH', 'POP', 'XCHG', 'IN', 'OUT', 'XLAT', 'LEA', 'LDS', 'LES', 'LAHF', 'SAHF', 'PUSHF',
                    'POPF']
    arithmetic_ins = ['ADD', 'SUB', 'MUL', 'DIV', 'XOR', 'INC', 'DEC', 'IMUL', 'IDIV', 'OR', 'NOT', 'SLL', 'SRL']
    calls_ins = ['CALL']

    no_transfer = 0
    no_arithmetic = 0
    no_calls = 0
    for ins in insns:
        ins_name = ins.insn_name()
        if in_ins_list(ins_name, transfer_ins):
            no_transfer = no_transfer + 1
        if in_ins_list(ins_name, arithmetic_ins):
            no_arithmetic = no_arithmetic + 1
        if in_ins_list(ins_name, calls_ins):
            no_calls = no_calls + 1
    return no_transfer, no_calls, no_arithmetic


def handle_block(block, no_str):
    """
    统计每个基本的特征
    :param block:
    :param no_str:
    :return:
    """
    # no of string constants
    no_string = no_str
    # no of numeric constants
    no_numeric = len(block.vex.constants)
    # no of instructions
    no_instructions = block.instructions
    # 指令集区分并计数
    no_transfer, no_calls, no_arithmetic = handle_ins(block.capstone.insns)
    # no of offspring
    no_offspring = 0
    return [no_string, no_numeric, no_transfer, no_calls, no_instructions, no_arithmetic, no_offspring]


def handle_function(entry_func, bin_path, output_path=None):
    """
    提取每个函数的特征并存储
    :param entry_func:
    :param bin_path:
    :param output_path:
    :return:
    """
    function_feature = dict()
    function_feature["bin_path"] = bin_path
    function_feature["function_name"] = entry_func.name
    function_feature["features"] = []
    function_feature["adj"] = []
    # no of string constants
    f_no_string = len(entry_func.string_references())
    block_cnt = 0
    # 提取函数内每个基本块的属性
    for blk in entry_func.blocks:
        function_feature["features"].append(handle_block(blk, f_no_string))
        block_cnt = block_cnt + 1
    function_feature["block"] = block_cnt
    # 节点数目为0时直接返回
    if 0 == len(entry_func.graph):
        return
    # 节点的邻接矩阵
    matrix = nx.adjacency_matrix(entry_func.graph).todense().tolist()
    for i, line in enumerate(matrix):
        # 当前节点到自己无边
        line[i] = 0
        no_offspring = line.count(1)
        function_feature["features"][i][-1] = no_offspring
        function_feature["adj"].append(line)
    if output_path is None:
        return function_feature
    else:
        with open(output_path, "a+", encoding="utf-8") as f:
            f.writelines(str(function_feature) + '\n')


def handle_bin(bin_file, output_path=None):
    if not os.path.isfile(bin_file):
        print("文件不存在->", bin_file)
        return
    db = None
    if output_path is None:
        client = pymongo.MongoClient(DBURL)
        db = client[DB]
    try:
        proj = angr.Project(bin_file, auto_load_libs=False)
        cfg = proj.analyses.CFGEmulated()
        # cfg = proj.analyses.CFGFast()
        for func in cfg.kb.functions.values():
            if output_path is not None:
                handle_function(cfg.kb.functions[func.addr], bin_file.strip(), output_path)
            else:
                feature = handle_function(cfg.kb.functions[func.addr], bin_file.strip())
                if feature is not None:
                    db[COL].insert(feature)
    except Exception as e:
        print("Exception->", bin_file)


def main_text(text):
    """
    从文本中逐行读取二进制程序的路径并进行处理
    :param text:
    :return:
    """
    if not os.path.isfile(text):
        print("文件不存在->", text)
        return
    pool = mp.Pool(processes=8)
    with open(text, "r") as f:
        for line in f:
            print("正在提取->", line)
            pool.apply_async(handle_bin, args=(line.strip(),))
        pool.close()
        pool.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="提取二进制程序特征")
    parser.add_argument('-v', '--version', action='version', version='acfg 1.0')
    parser.add_argument('-t', '--text', action='store_true', help='从文本中读取二进制程序路径')
    parser.add_argument('-o', '--output', type=str, default=None, help='=存储路径')
    parser.add_argument('inputFile', help='二进制文件或路径列表文件')
    args = parser.parse_args()

    # 输入为保存所有二进制程序路径的列表文件
    if args.text:
        main_text(args.inputFile)
        print("all task done!")
    else:
        if args.output is not None:
            handle_bin(args.inputFile, args.output)
            print("done->", args.output)
        else:
            print("请指定输出文件路径!")
