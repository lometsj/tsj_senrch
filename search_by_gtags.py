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
from sensetive import sensitive_problem
from overflow import overflow_problem
from command_inject import command_inject_problem
from mem_leak import mem_leak_problem

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CodeAnalyzer:
    """代码分析器，负责调用cscope生成代码关系数据"""

    def __init__(self, code_dir: str, data_dir: str):
        self.code_dir = os.path.abspath(code_dir)
        self.data_dir = os.path.abspath(data_dir)

    
            

    def generate_gtags_database(self):
        """生成GNU Global数据库"""
        logger.info("生成GNU Global数据库")
        subprocess.run(["gtags", "-i"], cwd=self.code_dir, check=True)
        
    def get_code_content(self, file, line, end):
        with open(os.path.join(self.code_dir,file),'r',encoding='utf-8',errors='ignore') as f:
            lines = f.readlines()
            return ''.join(lines[line-1:end])
    
    def get_ref_callee_content(self, file_path, line_num):
        print(f'f:{file_path} l:{line_num}')
        res = subprocess.run(
            ['ctags','--fields=+ne-P','--output-format=json','-o','-',file_path],
            cwd=self.code_dir,
            capture_output=True,
            text=True,
            check=True
        )
        syms = res.stdout.strip().split('\n')
        for sym in syms:
            try:
                sym_dict = json.loads(sym)
                if sym_dict['kind'] != 'function':
                    continue
                if line_num > sym_dict['line'] and sym_dict['end'] > line_num:
                    return self.get_code_content(file_path, sym_dict['line'], sym_dict['end'])
            except:
                print(sym_dict)
                

    def get_symbol_info(self, symbol: str) -> Dict:
        """获取符号的信息,先用global 看在哪些文件里，再用ctags获取具体的哈哈哈"""
        try:
            result = subprocess.run(
                ["global", "-x", symbol],
                cwd=self.code_dir,
                capture_output=True,
                text=True,
                check=True
            )
            
            lines = result.stdout.strip().split('\n')
            if not lines or lines[0] == '':
                return {"type": "unknown", "definition": "未找到定义"}
            ret = []
            for line in lines:
                parts = line.split(maxsplit=4)
                file = parts[2]
                # ctags --fields=+ne-P --output-format=json -o - test.c
                res = subprocess.run(
                    ['ctags','--fields=+ne-P','--output-format=json','-o','-',file],
                    cwd=self.code_dir,
                    capture_output=True,
                    text=True,
                    check=True
                )
                syms = res.stdout.strip().split('\n')
                for sym in syms:
                    sym_dict = json.loads(sym)
                    if sym_dict['name'] != symbol:
                        continue
                    sym_dict['content'] = self.get_code_content(file, sym_dict['line'], sym_dict['end'])
                    ret.append(sym_dict)
            return ret
        except Exception as e:
            logger.error(f"获取符号信息时出错: {str(e)}")
            logger.error(traceback.print_exc())
            return {"type": "error", "definition": str(e)}
    
    def find_all_refs(self, symbol: str) -> List[Dict]:
        """获取调用这个符号的caller的代码上下文"""
        try:
            result = subprocess.run(
                ["global", "-xsr", symbol],
                cwd=self.code_dir,
                capture_output=True,
                text=True,
                check=True
            )

            lines = result.stdout.strip().split('\n')
            # print(lines)
            if not lines or lines[0] == '':
                return []
            
            callers_content = []
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split(maxsplit=3)
                if len(parts) < 3:
                    continue
                
                callee, file_path, line_num, call_line =parts[0], parts[2], parts[1], parts[3]
                # logger.info(callee, file_path, line_num,call_line)
                # print(f'file={file_path} line_num={line_num}')
                caller_content = self.get_ref_callee_content(file_path, int(line_num))
                # print(caller_content)
                callers_content.append(caller_content)
                # refs.append({
                #     "callee": callee,
                #     "file": file_path,
                #     "line": int(line_num),
                #     "call_line": call_line,
                #     "caller_content": self.get_ref_callee_content(file_path, int(line_num))
                # })
            ret_content = list(dict.fromkeys(callers_content))
            ret_content = [item for item in ret_content if item is not None]

            return ret_content
            
        except Exception as e:
            logger.error(f"获取调用信息时出错: {str(e)}")
            logger.error(f"错误信息: {traceback.format_exc()}")
            return [] 

class LLMAnalyzer:
    """LLM分析器，负责与大模型交互分析日志函数是否打印敏感信息"""
    
    def __init__(self, code_analyzer: CodeAnalyzer, api_key: str, base_url: str, model: str
                 ):
        self.code_analyzer = code_analyzer
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        
        if api_key:
            openai.api_key = api_key
        # yes,indeed
        self.prompt_need = '''
【代码分析功能说明】
你可以使用get_symbol功能获取符号定义信息，可以使用find_refs获取函数引用信息以便于向上追踪函数调用栈。
具体请求格式见下面 `输出结果要求`。
【输出结果要求】
请在回答中包含带tsj的标签，以下标签三选一:
- 如判断有代码问题: [tsj_have] 并提供 {"problem_type": "问题类型", "context": "代码上下文"}
- 如判断无代码信息: [tsj_nothave]
- 如果不能判断，需要获取信息进一步分析，请包含[tsj_next]，并包含get_symbol或者find_refs请求获取更多代码信息,详细格式如下：
1. 如果需要知道某个函数，宏或者变量的定义，使用get_symbol获取符号信息: {"command": "get_symbol", "sym_name": "符号名称"}
2. 如果需要进一步分析数据流，使用find_refs获取调用信息: {"command": "find_refs", "sym_name\": "符号名称"}
'''
    
    def prepare_context(self, log_func: str, ref:List[str]) -> str:
        """准备用于查询LLM的上下文"""
        context = f"【任务背景】\n我将提供一个日志打印函数{log_func}的调用点, 这个函数的参数将会在日志中输出，请判断它是否打印了敏感信息（如密码、密钥、令牌等）。对于每一个参数，你应该详细分析该参数的来源来判断，比如如果打印某个变量，使用get_symbol获取该变量结构体，如果某个变量的值不确定为常量，使用find_refs获取调用函数信息向上追踪数据流，已经为你分析了整个代码库，所以你可以请求更多信息。\n\n"
        context += "【输出结果要求】\n"
        context += "请在回答中包含带tsj的标签，以下标签三选一:\n"
        context += "- 如判断有代码问题: [tsj_have] 并提供 {\"problem_type\": \"问题类型\", \"context\": \"代码上下文\"}\n"
        context += "- 如判断无代码信息: [tsj_nothave]\n"
        context += "- 如果不能判断，需要获取信息进一步分析，请包含[tsj_next]，并包含get_symbol或者find_refs请求获取更多代码信息,详细格式如下："
        context += "1. 如果需要知道某个函数，宏或者变量的定义，使用get_symbol获取符号信息: {\"command\": \"get_symbol\", \"sym_name\": \"符号名称\"}\n"
        context += "2. 如果需要进一步分析数据流，使用find_refs获取调用信息: {\"command\": \"find_refs\", \"sym_name\": \"符号名称\"}\n\n"

        context += str(ref)
        

        
        return context
    
    def process_llm_request(self, request: Dict) -> Dict:
        """处理LLM发出的信息请求"""
        logger.info("处理LLM发出的信息请求")
        if "command" not in request:
            return {"error": "缺少command字段"}
        
        if request["command"] == "get_symbol" and "sym_name" in request:
            return {
                "command": "get_symbol",
                "sym_name": request["sym_name"],
                "result": self.code_analyzer.get_symbol_info(request["sym_name"])
            }
        elif request["command"] == "find_refs" and "sym_name" in request:
            return {
                "command": "find_refs",
                "sym_name": request["sym_name"],
                "result": self.code_analyzer.find_all_refs(request["sym_name"])
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
    
    def analyze_task(self, problem_prompt):
        messages = [
            {"role": "system", "content": problem_prompt['system']},
            {"role": "user", "content": problem_prompt['init_user']+self.prompt_need}
        ]
        conversation_complete = False
        max_turns = 5  # 限制对话轮数
        turn = 0
        
        result = {
            "has_problem_info": False,
            "problem_info": None,
            "conversation": []
        }
        while not conversation_complete and turn < max_turns:
            llm_response = self.query_openai(messages)
            messages.append({"role":"assistant", "content": llm_response})
            if '[tsj_have]' in llm_response or '[tsj_nothave]' in llm_response:
                conversation_complete = True
                if '[tsj_have]' in llm_response:
                    result["has_problem_info"] = True
                try:
                    json_pattern = r'\{.*?\}'
                    for match in re.finditer(json_pattern, llm_response, re.DOTALL):
                        json_str = match.group(0)
                        problem_info = json.loads(json_str)
                        if "problem_type" in problem_info and "context" in problem_info:
                            result["problem_info"] = problem_info
                            break
                except Exception as e:
                    logger.warning(f"提取标签出错: {str(e)}")
            else:
                requests = self.extract_requests(llm_response)
                if len(requests) != 0:
                    responses = [self.process_llm_request(req) for req in requests]
                    response_message = "【代码分析系统回答】:\n\n" + json.dumps(responses, ensure_ascii=False, indent=2)
                    messages.append({"role": "user", "content": response_message})
                    logger.info(f"用户请求: {response_message}")
                else:
                    prompt = "请基于已有信息给出最终结论，是否包含敏感信息。记得包含[tsj_have]或[tsj_nothave]或[tsj_next]标记。"
                    messages.append({"role": "user", "content": prompt})
            turn += 1
        if turn == max_turns:
            result['has_problem_info'] = True
            result['problem_info'] = '对话轮数耗尽仍没有问答，建议重点审视。'

        result['conversation'] = messages
        return result


    def analyze_log_function(self, log_func: str, refs) -> List[Dict]:
        """分析单个日志函数的所有调用路径"""
        results = []
        
        for path_index, ref in enumerate(refs):
            logger.info(f"分析 {log_func} 的调用路径 {path_index+1}/{len(refs)}")
            
            # 初始化对话
            messages = [
                {"role": "system", "content": "你是一个代码安全分析专家，专注于识别代码中的敏感信息泄露。"},
                {"role": "user", "content": self.prepare_context(log_func, ref)}
            ]
            
            conversation_complete = False
            max_turns = 5  # 限制对话轮数
            turn = 0
            
            result = {
                "log_function": log_func,
                "path_index": path_index,
                "call": ref,
                "has_problem_info": False,
                "problem_info": None,
                "conversation": []
            }
            
            while not conversation_complete and turn < max_turns:
                turn += 1
                
                # 获取LLM响应
                llm_response = self.query_openai(messages)
                # logger.info(f"LLM响应: {llm_response}")
                
                # 检查是否结束对话
                if "[tsj_have]" in llm_response or "[tsj_nothave]" in llm_response:
                    logger.info("专业解说下判断了")
                    messages.append({"role": "assistant", "content": llm_response})
                    conversation_complete = True
                    
                    # 检查是否包含敏感信息
                    if "[tsj_have]" in llm_response:
                        result["has_problem_info"] = True
                        
                        # 尝试提取敏感信息的JSON
                        try:
                            json_pattern = r'\{.*?\}'
                            for match in re.finditer(json_pattern, llm_response, re.DOTALL):
                                json_str = match.group(0)
                                problem_info = json.loads(json_str)
                                if "problem_type" in problem_info and "context" in problem_info:
                                    result["problem_info"] = problem_info
                                    break
                        except Exception as e:
                            logger.warning(f"提取标签出错: {str(e)}")
                
                # 如果对话未结束，处理可能的请求
                if not conversation_complete:
                    requests = self.extract_requests(llm_response)
                    
                    if requests:
                        logger.info("需要进一步请求")
                        responses = [self.process_llm_request(req) for req in requests]
                        # logger.info(f"代码分析系统回答：{responses}")
                        response_message = "【代码分析系统回答】:\n\n" + json.dumps(responses, ensure_ascii=False, indent=2)
                        
                        messages.append({"role": "assistant", "content": llm_response})
                        messages.append({"role": "user", "content": response_message})
                        # logger.info(f"用户请求: {llm_response}")
                        logger.info(f"用户请求: {response_message}")
                    else:
                        # 如果没有请求但也没有结束标记，鼓励模型给出结论
                        prompt = "请基于已有信息给出最终结论，是否包含敏感信息。记得包含[tsj_have]或[tsj_nothave]或[tsj_next]标记。"
                        messages.append({"role": "assistant", "content": llm_response})
                        messages.append({"role": "user", "content": prompt})
                        
            result['conversation'] = messages
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
    
    

def main():
    parser = argparse.ArgumentParser(description='敏感信息日志打印分析工具')
    parser.add_argument('--code-dir', required=True, help='要分析的代码目录')
    parser.add_argument('--data-dir', default='./tsj_data', help='数据和报告输出目录')
    parser.add_argument('--config', default='./config.json', help='配置文件路径')

    
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
    

    code_analyzer.generate_gtags_database()
    
    # 获取日志函数调用路径
    log_functions = config.get("log_functions", [])
    max_depth = config.get("max_call_depth", 3)
    api_key = config.get("api_key",'')
    base_url = config.get("base_url",'')
    model = config.get("model", '')
    # 初始化LLM分析器
    llm_analyzer = LLMAnalyzer(code_analyzer, api_key, base_url, model)
    #################################register different type of vuln
    problem_type = [
        # sensitive_problem,
        # command_inject_problem,
        # overflow_problem,
        mem_leak_problem
    ]
    results = []
    for problem in problem_type:
        task_list = problem.get_task_list(config, code_analyzer)
        print(task_list)
        #todo batch mode
        for i in range(len(task_list)):
            task = task_list[i]
            result = llm_analyzer.analyze_task(problem.prepare_context(task))
            results.append(result)
    
    
    # refs_dict = {}
    # for log_function in log_functions:
    #     refs_dict[log_function] = code_analyzer.find_all_refs(log_function)
    #     print(refs_dict[log_function])
    
    
    
    # # 分析每个日志函数
    # results = {}
    # for log_func, refs in refs_dict.items():
    #     logger.info(f"使用LLM分析日志函数 {log_func} 的 {len(refs)} 条调用路径")
    #     results[log_func] = llm_analyzer.analyze_log_function(log_func, refs)
    
    # 处理结果
    result_processor = ResultProcessor(args.data_dir)
    result_file = result_processor.save_results(results)
    
    logger.info(f"分析完成！结果已保存到: {result_file}")


if __name__ == "__main__":
    main()
