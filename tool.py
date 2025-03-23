import re
import os
import sys
import subprocess

pre_line_num = 50
after_line_num = 10

def find_function_in_c_file(file_path, function_name):
    """
    使用cscope获取C/C++函数体
    
    Args:
        file_path: 要查找的文件路径
        function_name: 要查找的函数名
    
    Returns:
        str: 函数的完整定义和函数体，如果未找到则返回None
    """
    # 获取文件的目录
    file_dir = os.path.dirname(os.path.abspath(file_path))
    file_name = os.path.basename(file_path)

    try:
        # 使用cscope查找函数定义
        result = subprocess.run(
            ["cscope", "-d", "-L1", function_name, file_path], 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        lines = result.stdout.strip().split('\n')
        if not lines or lines[0] == '':
            print(f"未找到函数 {function_name} 的定义 cmd:cscope -d -L1 {function_name} {file_path}")
            return None
    
        
        if not len(lines):
            print(f"在文件 {file_name} 中未找到函数 {function_name} 的定义")
            return None
        line = lines[0]
        split_line = line.split(" ")
        line_num = split_line[2]
        line_num = int(line_num)
        
        # 读取源文件
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.readlines()
        
        if line_num > len(content):
            print(f"行号 {line_num} 超出文件行数 func:{function_name} file:{file_path} line:{line_num}")
            return None
        
        # 查找函数体开始位置(左大括号位置)
        func_start = line_num - 1  # cscope输出的行号从1开始
        left_brace_line = func_start
        while left_brace_line < len(content) and '{' not in content[left_brace_line]:
            left_brace_line += 1
        
        if left_brace_line >= len(content):
            print(f"未找到函数体的左大括号 func:{function_name} file:{file_path}")
            return None
        
        # 分析左大括号的位置，找到左大括号在行中的索引
        left_brace_pos = content[left_brace_line].find('{')
        
        # 找到匹配的右大括号
        brace_count = 1
        right_brace_line = left_brace_line
        
        while right_brace_line < len(content) and brace_count > 0:
            # 分析当前行右大括号之后的部分
            if right_brace_line == left_brace_line:
                line_to_check = content[right_brace_line][left_brace_pos+1:]
            else:
                line_to_check = content[right_brace_line]
                
            for char in line_to_check:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        break
            
            if brace_count > 0:
                right_brace_line += 1
        
        if brace_count > 0:
            print("未找到匹配的右大括号")
            return None
        
        # 提取完整函数体，包括函数声明
        function_body = ''.join(content[func_start:right_brace_line+1])
        
        return function_body
        
    except Exception as e:
        print(f"使用cscope查找函数失败: {str(e)}")
        return None
    
def get_context_of_function(file_path, function_name, line_num):
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