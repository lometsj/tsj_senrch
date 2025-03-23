#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import json
import re
import argparse
import traceback
from typing import List, Dict, Any, Tuple, Optional
import logging
import openai
import time
import html
import tool

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CodeAnalyzer:
    """代码分析器，负责调用cscope生成代码关系数据"""

    def __init__(self, code_dir: str, data_dir: str):
        self.code_dir = os.path.abspath(code_dir)
        self.data_dir = os.path.abspath(data_dir)
        self.cscope_db_path = os.path.join(self.code_dir, "cscope.out")
        
    def check_cscope_database(self) -> bool:
        """检查cscope数据库是否已存在"""
        return os.path.exists(self.cscope_db_path)
    
    def generate_cscope_database(self) -> bool:
        """生成cscope数据库"""
        try:
            logger.info(f"在目录 {self.code_dir} 中生成cscope数据库")
            
            # 切换到代码目录
            original_dir = os.getcwd()
            os.chdir(self.code_dir)
            
            # 生成文件列表
            subprocess.run(["find", ".", "-name", "*.c", "-o", "-name", "*.cpp", "-o", "-name", "*.h", "-o", "-name", "*.hpp"], 
                          stdout=open("cscope.files", "w"), check=True)
            
            # 生成cscope数据库
            subprocess.run(["cscope", "-b", "-q", "-k"], check=True)
            
            # 恢复原目录
            os.chdir(original_dir)
            
            return True
        except subprocess.SubprocessError as e:
            logger.error(f"生成cscope数据库失败: {str(e)}")
            return False
    
    def get_symbol_info(self, symbol: str) -> Dict:
        """获取符号的信息"""
        try:
            result = subprocess.run(
                ["cscope", "-d", "-L1", symbol], 
                cwd=self.code_dir,
                capture_output=True, 
                text=True, 
                check=True
            )
            
            lines = result.stdout.strip().split('\n')
            if not lines or lines[0] == '':
                return {"type": "unknown", "definition": "未找到定义"}
            
            # 简单分析第一行结果来确定符号类型
            parts = lines[0].split()
            if len(parts) < 2:
                return {"type": "unknown", "definition": "解析失败"}
            
            file_path, line_num = parts[0], parts[1]
            with open(os.path.join(self.code_dir, file_path), 'r', errors='ignore') as f:
                content = f.readlines()
            
            if int(line_num) <= len(content):
                definition_line = content[int(line_num) - 1].strip()
                
                # 尝试确定符号类型
                if "#define" in definition_line:
                    return {"type": "macro", "definition": definition_line}
                elif "struct" in definition_line and "{" in definition_line:
                    # 尝试获取完整的结构体定义
                    struct_def = definition_line
                    i = int(line_num)
                    while i < len(content) and "}" not in struct_def:
                        i += 1
                        if i <= len(content):
                            struct_def += "\n" + content[i-1].strip()
                    return {"type": "struct", "definition": struct_def}
                elif "(" in definition_line and ")" in definition_line and "{" in "".join(content[int(line_num)-1:int(line_num)+5]):
                    return {"type": "function", "definition": definition_line}
                else:
                    return {"type": "variable", "definition": definition_line}
            
            return {"type": "unknown", "definition": "无法读取定义行"}
            
        except Exception as e:
            logger.error(f"获取符号信息时出错: {str(e)}")
            return {"type": "error", "definition": str(e)}
    
    def get_call_by_info(self, symbol: str) -> List[Dict]:
        """获取符号被调用的信息"""
        try:
            result = subprocess.run(
                ["cscope", "-d", "-L3", symbol], 
                cwd=self.code_dir,
                capture_output=True, 
                text=True, 
                check=True
            )
            
            lines = result.stdout.strip().split('\n')
            if not lines or lines[0] == '':
                return []
            
            calls = []
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 3:
                    continue
                
                file_path,caller_func, line_num = parts[0], parts[1], parts[2]
                # context = tool.find_function_in_c_file(os.path.join(self.code_dir, file_path), caller_func)
                context = tool.get_context_of_function(os.path.join(self.code_dir, file_path), caller_func, int(line_num))
                                       
                calls.append({
                    "file": file_path,
                    "line": line_num,
                    "caller": caller_func,
                    "context": context
                })
            
            return calls
            
        except Exception as e:
            logger.error(f"获取调用信息时出错: {str(e)}")
            logger.error(f"错误信息: {traceback.format_exc()}")
            return []
    
    def find_call_paths(self, log_functions: List[str], max_depth: int = 3) -> Dict[str, List[List[Dict]]]:
        """为每个日志函数找到调用路径"""
        result = {}
        
        for log_func in log_functions:
            logger.info(f"分析日志函数: {log_func}")
            result[log_func] = []
            
            # 获取直接调用该日志函数的函数
            direct_calls = self.get_call_by_info(log_func)
            
            for call in direct_calls:
                path = [{"function": log_func, **call}]
                
                # 向上追溯调用路径
                current_func = call["caller"]
                current_depth = 1
                
                while current_func != "main" and current_depth < max_depth:
                    upper_calls = self.get_call_by_info(current_func)
                    
                    if not upper_calls:
                        break
                    
                    # 只取第一个调用者，简化处理
                    # 实际中可能需要处理多个调用路径
                    path.append({
                        "function": current_func,
                        **upper_calls[0]
                    })
                    
                    current_func = upper_calls[0]["caller"]
                    current_depth += 1
                
                result[log_func].append(path)
        
        return result

class LLMAnalyzer:
    """LLM分析器，负责与大模型交互分析日志函数是否打印敏感信息"""
    
    def __init__(self, code_analyzer: CodeAnalyzer, api_key: str = 'sk-8b17d606cd9b499595f5f6af44eb58e8', base_url: str = 'https://api.deepseek.com/v1', model: str = 'deepseek-reasoner'):
        self.code_analyzer = code_analyzer
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        
        if api_key:
            openai.api_key = api_key
    
    def prepare_context(self, log_func: str, call_path: List[Dict]) -> str:
        """准备用于查询LLM的上下文"""
        context = f"我将提供一个日志打印函数{log_func}的调用路径, 这个函数的参数将会在日志中输出，请判断它是否打印了敏感信息（如密码、密钥、令牌等）：\n\n"
        
        # 反转调用路径，从最上层调用者开始
        for i, call in enumerate(reversed(call_path)):
            context += f"调用层级 {i+1}：\n"
            context += f"文件: {call['file']}, 行号: {call['line']}\n"
            context += f"函数: {call['function']}\n"
            context += f"代码上下文: {call['context']}\n\n"
        
        context += "请分析上述代码路径，判断最终的日志打印是否包含敏感信息。如果需要更多信息，请使用以下JSON格式请求：\n"
        context += "1. 获取符号信息: {\"command\": \"get_symbol\", \"sym_name\": \"符号名称\"}\n"
        context += "2. 获取调用信息: {\"command\": \"call_by\", \"sym_name\": \"符号名称\"}\n\n"
        context += "如果确定是否包含敏感信息，请在回答中包含:\n"
        context += "- 如有敏感信息: [tsj_have] 并提供 {\"sensitive_type\": \"敏感类型\", \"context\": \"代码上下文\"}\n"
        context += "- 如无敏感信息: [tsj_nothave]\n"
        context += "- 分析完成后请包含: [tsj_end]\n"
        
        return context
    
    def process_llm_request(self, request: Dict) -> Dict:
        """处理LLM发出的信息请求"""
        if "command" not in request:
            return {"error": "缺少command字段"}
        
        if request["command"] == "get_symbol" and "sym_name" in request:
            return {
                "command": "get_symbol",
                "sym_name": request["sym_name"],
                "result": self.code_analyzer.get_symbol_info(request["sym_name"])
            }
        elif request["command"] == "call_by" and "sym_name" in request:
            return {
                "command": "call_by",
                "sym_name": request["sym_name"],
                "result": self.code_analyzer.get_call_by_info(request["sym_name"])
            }
        else:
            return {"error": "未知命令或缺少必要参数"}
    
    def extract_requests(self, llm_response: str) -> List[Dict]:
        """从LLM响应中提取JSON请求"""
        requests = []
        json_pattern = r'\{.*?\}'
        
        # 查找可能的JSON对象
        for match in re.finditer(json_pattern, llm_response, re.DOTALL):
            try:
                json_str = match.group(0)
                req = json.loads(json_str)
                if isinstance(req, dict) and "command" in req:
                    requests.append(req)
            except json.JSONDecodeError:
                continue
        
        return requests
    
    def query_openai(self, messages: List[Dict]) -> str:
        """调用OpenAI API进行查询"""
        try:
            # 添加重试机制
            max_retries = 3
            retry_delay = 2
            
            for attempt in range(max_retries):
                try:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=messages,
                        temperature=0.1,  # 低温度以获得更确定的回答
                        max_tokens=2000,  # 设置最大token数
                        top_p=0.95,  # 设置top_p参数
                        frequency_penalty=0,  # 设置frequency_penalty参数
                        presence_penalty=0,  # 设置presence_penalty参数
                    )
                    return response.choices[0].message.content
                except (openai.RateLimitError, openai.APIError) as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"API调用失败，尝试重试 ({attempt+1}/{max_retries}): {str(e)}")
                        time.sleep(retry_delay * (2 ** attempt))  # 指数退避
                    else:
                        raise
        except Exception as e:
            logger.error(f"调用OpenAI API时出错: {str(e)}")
            logger.error(f"错误信息: {traceback.format_exc()}")
            return f"API调用错误: {str(e)}"
    
    def analyze_log_function(self, log_func: str, call_paths: List[List[Dict]]) -> List[Dict]:
        """分析单个日志函数的所有调用路径"""
        results = []
        
        for path_index, call_path in enumerate(call_paths):
            logger.info(f"分析 {log_func} 的调用路径 {path_index+1}/{len(call_paths)}")
            
            # 初始化对话
            messages = [
                {"role": "system", "content": "你是一个代码安全分析专家，专注于识别代码中的敏感信息泄露。"},
                {"role": "user", "content": self.prepare_context(log_func, call_path)}
            ]
            
            conversation_complete = False
            max_turns = 5  # 限制对话轮数
            turn = 0
            
            result = {
                "log_function": log_func,
                "path_index": path_index,
                "call_path": call_path,
                "has_sensitive_info": False,
                "sensitive_info": None,
                "conversation": []
            }
            
            while not conversation_complete and turn < max_turns:
                turn += 1
                
                # 获取LLM响应
                llm_response = self.query_openai(messages)
                logger.info(f"LLM响应: {llm_response}")
                result["conversation"].append({"role": "assistant", "content": llm_response})
                
                # 检查是否结束对话
                if "[tsj_end]" in llm_response:
                    conversation_complete = True
                    
                    # 检查是否包含敏感信息
                    if "[tsj_have]" in llm_response:
                        result["has_sensitive_info"] = True
                        
                        # 尝试提取敏感信息的JSON
                        try:
                            json_pattern = r'\{.*?\}'
                            for match in re.finditer(json_pattern, llm_response, re.DOTALL):
                                json_str = match.group(0)
                                sensitive_info = json.loads(json_str)
                                if "sensitive_type" in sensitive_info and "context" in sensitive_info:
                                    result["sensitive_info"] = sensitive_info
                                    break
                        except Exception as e:
                            logger.warning(f"提取敏感信息时出错: {str(e)}")
                
                # 如果对话未结束，处理可能的请求
                if not conversation_complete:
                    requests = self.extract_requests(llm_response)
                    
                    if requests:
                        responses = [self.process_llm_request(req) for req in requests]
                        response_message = "以下是请求的附加信息:\n\n" + json.dumps(responses, ensure_ascii=False, indent=2)
                        
                        messages.append({"role": "assistant", "content": llm_response})
                        messages.append({"role": "user", "content": response_message})
                        logger.info(f"用户请求: {llm_response}")
                        logger.info(f"用户请求: {response_message}")
                        result["conversation"].append({"role": "user", "content": response_message})
                    else:
                        # 如果没有请求但也没有结束标记，鼓励模型给出结论
                        prompt = "请基于已有信息给出最终结论，是否包含敏感信息。记得包含[tsj_have]或[tsj_nothave]和[tsj_end]标记。"
                        messages.append({"role": "assistant", "content": llm_response})
                        messages.append({"role": "user", "content": prompt})
                        
                        result["conversation"].append({"role": "user", "content": prompt})
            
            results.append(result)
        
        return results

class ResultProcessor:
    """结果处理器，负责生成结果数据和HTML报告"""
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
    
    def save_results(self, results: Dict) -> str:
        """保存分析结果到JSON文件"""
        timestamp = time.strftime("%Y%m%d%H%M%S")
        result_file = os.path.join(self.data_dir, f"analysis_result_{timestamp}.json")
        
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        return result_file
    
    def generate_html_report(self, results: Dict, output_file: str = None) -> str:
        """生成HTML报告"""
        if not output_file:
            timestamp = time.strftime("%Y%m%d%H%M%S")
            output_file = os.path.join(self.data_dir, f"report_{timestamp}.html")
        
        # 简单HTML模板
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>敏感信息日志打印分析报告</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background-color: #f0f0f0; padding: 10px; margin-bottom: 20px; }}
                .log-function {{ margin-bottom: 30px; border: 1px solid #ccc; padding: 10px; }}
                .path {{ margin-bottom: 20px; padding: 10px; border-left: 3px solid #ddd; }}
                .sensitive {{ background-color: #ffdddd; }}
                .safe {{ background-color: #ddffdd; }}
                .highlight {{ background-color: yellow; font-weight: bold; }}
                .call-path {{ font-family: monospace; white-space: pre; }}
                .conversation {{ border: 1px solid #eee; padding: 10px; margin-top: 10px; }}
                .assistant {{ background-color: #e6f7ff; }}
                .user {{ background-color: #f0f0f0; }}
                .message {{ padding: 5px; margin: 5px 0; }}
                .sensitive-info {{ color: red; font-weight: bold; }}
                details {{ margin-bottom: 10px; }}
                summary {{ cursor: pointer; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>敏感信息日志打印分析报告</h1>
            <div class="summary">
                <h2>分析摘要</h2>
                <p>分析时间: {timestamp}</p>
                <p>分析的日志函数数量: {log_func_count}</p>
                <p>发现敏感信息的函数数量: {sensitive_count}</p>
            </div>
            
            <h2>详细分析结果</h2>
            {detailed_results}
        </body>
        </html>
        """
        
        detailed_results = ""
        sensitive_count = 0
        log_func_count = len(results)
        
        for log_func, func_results in results.items():
            has_sensitive = any(r["has_sensitive_info"] for r in func_results)
            sensitive_count += 1 if has_sensitive else 0
            
            function_class = "sensitive" if has_sensitive else "safe"
            
            detailed_results += f'<div class="log-function {function_class}">\n'
            detailed_results += f'<h3>日志函数: {html.escape(log_func)}</h3>\n'
            if has_sensitive:
                detailed_results += '<p>状态: "<span class=\"sensitive-info\">包含敏感信息</span> </p>\n'
            else:
                detailed_results += '<p>状态: "<span>安全</span> </p>\n'
            detailed_results += f'<p>调用路径数: {len(func_results)}</p>\n'
            
            for idx, result in enumerate(func_results):
                path_class = "sensitive" if result["has_sensitive_info"] else "safe"
                
                detailed_results += f'<div class="path {path_class}">\n'
                detailed_results += f'<h4>调用路径 {idx+1}</h4>\n'
                
                # 显示调用路径
                detailed_results += '<details>\n<summary>调用路径详情</summary>\n'
                detailed_results += '<div class="call-path">\n'
                
                for i, call in enumerate(reversed(result["call_path"])):
                    detailed_results += f'层级 {i+1}:\n'
                    detailed_results += f'  文件: {html.escape(call["file"])}, 行号: {call["line"]}\n'
                    detailed_results += f'  函数: {html.escape(call["function"])}\n'
                    
                    # 如果存在敏感信息，高亮显示
                    context = call["context"]
                    if result["has_sensitive_info"] and result["sensitive_info"] and \
                       "context" in result["sensitive_info"] and context in result["sensitive_info"]["context"]:
                        context = f'<span class="highlight">{html.escape(context)}</span>'
                    else:
                        context = html.escape(context)
                    
                    detailed_results += f'  代码: {context}\n\n'
                
                detailed_results += '</div>\n</details>\n'
                
                # 显示敏感信息
                if result["has_sensitive_info"] and result["sensitive_info"]:
                    detailed_results += '<div class="sensitive-info">\n'
                    detailed_results += f'<p>敏感信息类型: {html.escape(result["sensitive_info"].get("sensitive_type", "未指定"))}</p>\n'
                    detailed_results += f'<p>相关上下文: {html.escape(result["sensitive_info"].get("context", ""))}</p>\n'
                    detailed_results += '</div>\n'
                
                # 显示对话历史
                detailed_results += '<details>\n<summary>分析对话历史</summary>\n'
                detailed_results += '<div class="conversation">\n'
                
                for msg in result["conversation"]:
                    role_class = "assistant" if msg["role"] == "assistant" else "user"
                    detailed_results += f'<div class="message {role_class}">\n'
                    detailed_results += f'<strong>{msg["role"].capitalize()}:</strong><br>\n'
                    detailed_results += html.escape(msg["content"]).replace("[tsj_have]", "<span class=\'sensitive-info\'>[敏感信息]</span>").replace("[tsj_nothave]", "<span>[无敏感信息]</span>").replace("[tsj_end]", "<span>[分析结束]</span>").replace("\n", "<br>")
                    detailed_results += '</div>\n'
                
                detailed_results += '</div>\n</details>\n'
                detailed_results += '</div>\n'  # end path
            
            detailed_results += '</div>\n'  # end log-function
        
        # 填充模板
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        html_content = html_content.format(
            timestamp=timestamp,
            log_func_count=log_func_count,
            sensitive_count=sensitive_count,
            detailed_results=detailed_results
        )
        
        # 写入文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file

def main():
    parser = argparse.ArgumentParser(description='敏感信息日志打印分析工具')
    parser.add_argument('--code-dir', required=True, help='要分析的代码目录')
    parser.add_argument('--data-dir', default='./tsj_data', help='数据和报告输出目录')
    parser.add_argument('--config', default='./config.json', help='配置文件路径')
    parser.add_argument('--api-key', help='OpenAI API密钥')
    
    args = parser.parse_args()
    
    # 确保输出目录存在
    os.makedirs(args.data_dir, exist_ok=True)
    
    # 加载配置
    if not os.path.exists(args.config):
        # 创建默认配置
        default_config = {
            "log_functions": ["printf", "fprintf", "log_info", "log_error", "printk"],
            "max_call_depth": 3
        }
        with open(args.config, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2)
        
        logger.info(f"已创建默认配置文件: {args.config}")
    
    with open(args.config, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    # 初始化代码分析器
    code_analyzer = CodeAnalyzer(args.code_dir, args.data_dir)
    
    # 检查cscope数据库
    if not code_analyzer.check_cscope_database():
        logger.info("未找到现有的cscope数据库，正在生成...")
        if not code_analyzer.generate_cscope_database():
            logger.error("无法生成cscope数据库，请确保cscope已安装并检查代码目录")
            return
    else:
        logger.info("使用现有的cscope数据库")
    
    # 获取日志函数调用路径
    log_functions = config.get("log_functions", [])
    max_depth = config.get("max_call_depth", 10)
    
    logger.info(f"分析以下日志函数: {', '.join(log_functions)}")
    call_paths = code_analyzer.find_call_paths(log_functions, max_depth)

    # 结构化输出调用路径
    for log_func, paths in call_paths.items():
        print(f"\n日志函数: {log_func}")
        print("-" * 50)
        for i, path in enumerate(paths, 1):
            print(f"\n调用路径 {i}:")
            for j, call in enumerate(path, 1):
                print(f"\n  调用层级 {j}:")
                print(f"  文件: {call['file']}")
                print(f"  行号: {call['line']}")
                print(f"  调用函数: {call['caller']}")
                print(f"  上下文:\n{call['context']}")
    
    # 初始化LLM分析器
    llm_analyzer = LLMAnalyzer(code_analyzer, args.api_key)
    
    # 分析每个日志函数
    results = {}
    for log_func, paths in call_paths.items():
        logger.info(f"使用LLM分析日志函数 {log_func} 的 {len(paths)} 条调用路径")
        results[log_func] = llm_analyzer.analyze_log_function(log_func, paths)
    
    # 处理结果
    result_processor = ResultProcessor(args.data_dir)
    result_file = result_processor.save_results(results)
    report_file = result_processor.generate_html_report(results)
    
    logger.info(f"分析完成！结果已保存到: {result_file}")
    logger.info(f"HTML报告已生成: {report_file}")
    logger.info(f"请在浏览器中打开HTML报告查看详细分析结果")

if __name__ == "__main__":
    main()
