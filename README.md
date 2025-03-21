# 敏感信息日志打印分析工具

这是一个使用大语言模型(LLM)来分析C/C++代码中日志打印函数是否包含敏感信息的工具。该工具通过分析代码调用关系，追踪日志打印函数的调用路径，并使用LLM来判断是否有敏感信息（如密码、密钥等）被打印。

## 功能特点

- 自动分析C/C++代码库中的日志打印函数
- 基于cscope生成代码调用关系
- 支持多轮对话，让LLM深入分析代码上下文
- 生成详细的HTML报告，高亮显示可能泄露敏感信息的代码位置
- 保存分析结果为JSON格式，方便后续处理

## 安装依赖

```bash
pip install openai argparse
```

同时需要确保系统已安装cscope工具：

- 在Ubuntu/Debian系统上：`sudo apt-get install cscope`
- 在CentOS/RHEL系统上：`sudo yum install cscope`
- 在macOS系统上：`brew install cscope`
- 在Windows系统上：可通过cygwin或WSL安装

## 使用方法

1. 准备配置文件（可选，不提供时会使用默认配置）
   
   创建`config.json`文件：
   ```json
   {
     "log_functions": ["printf", "fprintf", "log_info", "log_error", "printk"],
     "max_call_depth": 3
   }
   ```

2. 运行分析工具

   ```bash
   python senrch.py --code-dir /path/to/your/code --api-key YOUR_OPENAI_API_KEY
   ```

   参数说明：
   - `--code-dir`：要分析的代码目录（必选）
   - `--data-dir`：数据和报告输出目录（可选，默认为`./tsj_data`）
   - `--config`：配置文件路径（可选，默认为`./config.json`）
   - `--api-key`：OpenAI API密钥

3. 查看分析结果

   分析完成后，工具会在`--data-dir`指定的目录下生成HTML报告和JSON结果文件。打开HTML报告可以查看详细的分析结果。

## 分析流程

1. 检查代码目录是否已经生成过cscope数据库，如果没有则调用cscope生成
2. 根据配置文件中的日志打印函数列表，对每个函数分析其调用路径
3. 将调用路径作为上下文，询问LLM该日志打印是否包含敏感信息
4. LLM可以通过JSON格式请求获取更多代码上下文信息
5. 根据LLM的分析结果，生成最终报告

## 注意事项

- 需要OpenAI API密钥才能使用LLM分析功能
- 分析大型代码库可能需要较长时间
- 工具分析结果仅供参考，建议专业人员进行二次确认

## 示例输出

分析完成后，HTML报告将包含：
- 敏感信息摘要统计
- 每个日志函数的详细分析
- 可能包含敏感信息的代码路径高亮显示
- 分析过程中的LLM对话历史

## 贡献

欢迎提交问题报告和改进建议！
