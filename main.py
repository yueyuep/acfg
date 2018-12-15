#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import angr
import os
from angrutils import *


def test(bin_file):
    if not os.path.isfile(bin_file):
        print("文件不存在->", bin_file)
        return
    proj = angr.Project(bin_file, auto_load_libs=False)

    # cfg = proj.analyses.CFGFast()
    cfg = proj.analyses.CFGEmulated(keep_state=True)
    funcs = cfg.kb.functions

    # 获取函数地址和函数名
    # for func in proj.kb.functions.values():
    #     print(func.addr, func.name)

    # result = dict(proj.kb.functions)
    # print(result)
    print(cfg)


if __name__ == "__main__":
    print("angr start")
    test("data/cgibin")
