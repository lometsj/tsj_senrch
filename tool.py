import re
import os
import sys
import subprocess

pre_line_num = 50
after_line_num = 10


    
def get_context_of_function(file_path, line_num):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        file_num = len(lines)
        start_line = line_num-pre_line_num
        if start_line<0:
            start_line=0
        end_line = line_num+after_line_num
        if end_line>file_num:
            end_line = file_num
        ret = lines[start_line:end_line]
        return "".join(ret)
def main():
    file_path = sys.argv[1]
    function_name = sys.argv[2]

    function_body = find_function_in_c_file(file_path, function_name)

    if function_body:
        print("\n找到的函数体:")
        print(function_body)
    else:
        print("\n未找到该函数的定义。")

if __name__ == "__main__":
    main()