# acfg
Extracting the ACFG feature of each function from the binary file based on angr.

基于angr从二进制文件中提取每个函数的ACFG特征。

## Install
```python
pip3 install -r requirements.txt
```

## Usage
```bash
python3 main.py -h

usage: main.py [-h] [-v] [-t] [-o OUTPUT] inputFile

提取二进制程序特征

positional arguments:
  inputFile             二进制文件或路径列表文件

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -t, --text            从文本中读取二进制程序路径
  -o OUTPUT, --output OUTPUT
                        =存储路径
```

## Example

### From single binary
```bash
python3 main.py -o result.txt data/busybox
```

### From massive binary
```bash
# The result is stored in the database by default.
# Each line in the text "input.txt" represents the path of a binary file.
python3 main.py -t input.txt
```