class overflow_problem:
    def get_task_list(config, code_analyzer):
        exec_funcs = ['memcpy','strcpy','gets','sprintf','scanf','read']
        task_list = []
        for func in exec_funcs:
            refs = code_analyzer.find_all_refs(func)
            print(f'{func}:{refs}')
            for ref in refs:
                task = {}
                task['func'] = func
                task['content'] = ref
                task_list.append(task)
        return task_list
    def prepare_context(task):
        log_func = task['func']
        prompt = {}
        prompt['system'] = '你是一个代码安全分析专家，专注于识别代码中的缓冲区溢出问题。'
        prompt['init_user'] = f"""【任务背景】
我将提供一个缓冲区操作函数{log_func}的调用点代码，请判断它是否有缓冲区溢出风险。
一般的方法是检查被操作的dest缓冲区长度与长度参数是否相符，如果不相符就有溢出风险。
【例子】
memcpy(dest,src,count);
如果count大于dest的缓冲区长度的话就有缓冲区溢出问题。
【各个缓冲区函数的签名，供参考】
void *memcpy(void *dest, const void *src, size_t n);
char *strcpy(char *destination, const char *source);
char *gets(char *dest_str);
int sprintf(char *str, const char *format, ...);
int scanf(const char *format, ...);
ssize_t read (int fd, void * buf, size_t count); 
【待分析的代码】
{task['content']}
"""
        return prompt