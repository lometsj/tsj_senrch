class sensitive_problem:
    def get_task_list(config, code_analyzer):
        log_functions = config.get('log_functions',[])
        task_list = []
        for func in log_functions:
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
        prompt['system'] = '你是一个代码安全分析专家，专注于识别代码中的敏感信息泄露。'
        prompt['init_user'] = f"""【任务背景】
我将提供一个日志打印函数{log_func}的调用点代码, 这个函数的参数将会在日志中输出，请判断它是否打印了敏感信息（如密码、密钥、令牌等）。
对于每一个参数，你应该详细分析该参数的来源来判断，比如如果打印某个变量，分析该变量是否包含敏感信息。
【供参考的敏感信息pattern】
[
    "password",
    "passwd",
    "pswd",
    "secret",
    "token",
    "key",
    "证书",
    "私钥",
    "auth"
    "private_key",
    ]
【例子1】
如果该变量为结构体，应该使用查看定义功能get_symbol查看该结构体是否包含敏感信息成员。比如有代码：
```
struct task example;
print_task(example);
```
此时应该使用get_symbol功能获取task结构体的定义，比如获取到task结构体定义为
```
struct task{{
    char task_device_passwd[10];
    int task_id;
}}
```
那么虽然example看起来没有敏感信息，但其实多分析一点可以发现其实是有敏感信息passwd打印的。
【例子2】
如果有被打印的变量来自函数参数即上一层函数传递下来的，应该使用查找函数引用功能find_refs查看调用函数如何组装该变量并传递下来的。比如有代码：
```
void kill_task(char *task_id){{
    print_log("%s",task_id);
}}
```
此时应该使用find_refs功能获取kill_task的引用信息，查看caller函数如何调用kill_task函数，比如获取到的引用信息为
```
void task_manager(){{
    int id = 123;
    char task_id[100] = {0};
    char password[] = get_password_from_db();
    sprintf(task_id,"%s_%d",password,id);
    kill_task(task_id);
}}
```
那么虽然task_id看起来没有敏感信息，但其实多分析一点可以发现其实是有敏感信息password打印的。
【待分析的代码】
{task['content']}
"""
        return prompt