class mem_leak_problem:
    def get_task_list(config, code_analyzer):
        alloc_funcs = [
            ('malloc','free')
        ]
        task_list = []
        for func in alloc_funcs:
            refs = code_analyzer.find_all_refs(func[0])
            for ref in refs:
                task = {}
                task['func'] = func
                task['content'] = ref
                task_list.append(task)
        return task_list
    def prepare_context(task):
        malloc_func = task['func'][0]
        free_func = task['func'][1]
        prompt = {}
        prompt['system'] = '你是一个代码安全分析专家，专注于识别代码中的内存泄露问题。'
        prompt['init_user'] = f"""【任务背景】
我将提供一个内存申请函数{malloc_func}的调用点代码, 这个函数会动态申请内存，并由{free_func}，请判断该内存申请后有没有释放，如果没有释放，就有内存泄露问题。
【注意】
你应该只分析单函数场景是否有内存泄露问题，比如异常分支没有释放，局部变量持有的内在存函数return前没有释放。
如果内存申请后，作为参数或者返回值传出，表示该动态内存的生命周期不止存在于这个函数，这种情况不用继续分析，直接判断没有内存泄露问题即可。
【待分析的代码】
{task['content']}
"""
        return prompt