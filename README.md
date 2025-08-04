# 大模型代码分析和审计工具

这是一个使用大语言模型(LLM)来分析C/C++代码中。该工具通过分析代码调用关系（基于ctags cscope等），并使用LLM来判断代码安全问题。

## something


- 基于cscope生成代码调用关系
- 支持多轮对话，让LLM深入分析代码上下文
- 生成详细的HTML报告，高亮显示可能泄露敏感信息的代码位置
- 保存分析结果为JSON格式，方便后续处理

## 安装依赖

```bash
pip install openai argparse
```

同时需要确保系统已安装cscope工具：

- 在Ubuntu/Debian系统上：`sudo apt-get install cscope universal-ctags`
- 在CentOS/RHEL系统上：`sudo yum install cscope universal-ctags`
- 在macOS系统上：`brew install cscope universal-ctags`
- 在Windows系统上：可通过cygwin或WSL安装

## 使用方法

1. 准备配置文件
   
   创建`config.json`文件：
   ```json
   {
   "log_functions": ["print_log"],
   "max_call_depth": 10,
   "base_url":"http://192.168.1.1:11434/v1/",
   "api_key":"123",
   "model":"qwen2.5-coder"
   } 
   ```
2. 使用ctags和cscope建立tags数据库
```
cd /path/to/code/dir
find . -type f \( -name "*.c" -o -name "*.h" \) > fileslist
mkdir .tsj
ctags -L fileslist -o .tsj/tags
cscope -kbq -i fileslist 
```

2. 运行分析工具

   ```bash
   python main.py --code-dir /path/to/your/code --config /path/to/config
   ```

   参数说明：
   - `--code-dir`：要分析的代码目录（必选）
   - `--data-dir`：数据和报告输出目录（可选，默认为`./tsj_data`）
   - `--config`：配置文件路径（可选，默认为`./config.json`）

3. 查看分析结果

   分析完成后，工具会在`--data-dir`指定的目录下生成JSON结果文件。通过index.html打开json解析并查看报告


## 注意事项

- 需要OpenAI API密钥才能使用LLM分析功能
- 分析大型代码库可能需要较长时间
- 工具分析结果仅供参考，建议专业人员进行二次确认
