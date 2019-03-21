# acfg
Extracting the ACFG feature of each function from the binary file based on angr.

基于angr从二进制文件中提取每个函数的ACFG特征。

<p align="center">
    <img src="https://raw.githubusercontent.com/mayuanucas/acfg/master/data/acfg.svg"/>
</p>

## Install
```python
pip3 install -r requirements.txt
```

## Usage
```bash
python3 main.py -h

usage: main.py [-h] [-v] [-o OUTPUT] inputFile

提取二进制程序特征

positional arguments:
  inputFile             二进制文件

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -o OUTPUT, --output OUTPUT
                        =存储目录
```

## Example

### From single binary
```bash
python3 main.py -o ./out/ data/busybox
```