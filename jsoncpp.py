# https://github.com/search?q=%23include+%3Cjson%2Fjson.h%3E&type=code
class jsoncpp_problem:
    def get_task_list(config, code_analyzer):
        jsoncpp_funcs = [
            'asString',
            'asCstring'
        ]
        task_list = []
        for func in jsoncpp_funcs:
            refs = code_analyzer.find_all_refs(func)
            for ref in refs:
                task = {}
                task['func'] = func
                task['content'] = ref
                task_list.append(task)
        return task_list
    def prepare_context(task):
        json_func = task['func']
        prompt = {}
        prompt['system'] = '你是一个代码安全分析专家tsj，专注于识别jsoncpp代码中的安全问题。'
        prompt['init_user'] = f"""【任务背景】
我将提供一个jsoncpp库函数{json_func}的调用点代码, 这个函数会将jsoncpp节点转换为字符串类型，如果转换前没有使用isString判断节点类型，就会有段错误问题。
你的任务就是检查调用点代码在调用{json_func}前是否使用isString判断节点类型。
"""
        prompt['init_user'] = prompt['init_user'] + '''
【例子】
```
int main() {
    std::ifstream ifs("test.json");
    if (!ifs.is_open()) {
        std::cerr << "Failed to open test.json" << std::endl;
        return 1;
    }

    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();

    // 解析 JSON 数据
    Json::Value root;
    Json::CharReaderBuilder reader;
    std::string errs;
    std::istringstream s(content);
    if (!Json::parseFromStream(reader, s, &root, &errs)) {
        std::cerr << "Failed to parse JSON: " << errs << std::endl;
        return 1;
    }

    // 假设 JSON 文件中有一个名为 "name" 的字符串节点
    if (root.isMember("name")) {
        std::string name = root["name"].asString();
        std::cout << "Name: " << name << std::endl;
    } else {
        std::cerr << "No valid 'name' string found in JSON" << std::endl;
    }

    return 0;
}
```
在这个例子里，调用点代码在调用asString前没有使用isString判断节点类型，就会有段错误问题。
【强制分析要求】
像例子里一样，必须分析root["name"]在调用asString前是否使用isString判断节点类型。
如果代码给出的是asCstring，也是同理
'''
        prompt['init_user'] = prompt['init_user'] + f'''
【待分析的代码】
{task['content']}
'''
        return prompt
