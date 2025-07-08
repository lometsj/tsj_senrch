class command_inject_problem:
    def get_task_list(config, code_analyzer):
        exec_funcs = ['system','popen','execl','execlp','execle','execv','execvp','execve']
        task_list = []
        for func in exec_funcs:
            refs = code_analyzer.find_all_refs(func)
            for ref in refs:
                task = {}
                task['func'] = func
                task['content'] = ref
                task_list.append(task)
        return task_list
    def prepare_context(task):
        log_func = task['func']
        prompt = {}
        prompt['system'] = '你是一个代码安全分析专家，专注于识别代码中的命令注入问题。'
        prompt['init_user'] = f"""【任务背景】
我将提供一个命令注入函数{log_func}的调用点代码, 这个函数将会根据输入参数执行命令，请判断它的命令行字符串是否可以被外部数据控制，从而有命令注入的风险。
【什么是外部数据】
进程外部数据：从IPC通信如共享内存、消息队列、unix domian socket传来的数据
本机外部数据：从网络socket recv收上来的数据，tcp，udp通信传来的数据
【待分析的代码】
{task['content']}
"""
        return prompt