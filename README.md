# API Key Leak Detector

一个用于扫描GitHub公开仓库中API密钥泄露的安全工具。它可以自动检测各种类型的API密钥，并通知仓库作者进行处理。

## 功能特性

- 🔍 **自动扫描**：定期扫描GitHub公开仓库中的API密钥泄露
- 🎯 **多种密钥类型**：支持AWS、Azure、GCP、GitHub、数据库等多种密钥类型检测
- 🛡️ **智能过滤**：减少误报，提高检测准确性
- 📬 **多种通知方式**：支持GitHub Issue、邮件通知等多种方式
- 📊 **详细报告**：生成结构化的扫描报告
- ⏰ **定时运行**：支持GitHub Action定时扫描

## 支持的密钥类型

| 密钥类型 | 严重程度 | 说明 |
|---------|---------|------|
| AWS Access Key | Critical | AWS访问密钥 |
| AWS Secret Key | Critical | AWS秘密访问密钥 |
| Azure Storage Key | Critical | Azure存储账户密钥 |
| Azure Client Secret | Critical | Azure客户端密钥 |
| GCP API Key | Critical | Google Cloud API密钥 |
| GitHub Token | Critical | GitHub个人访问令牌 |
| Database URL | Critical | 数据库连接字符串 |
| Private Key | Critical | SSH/RSA私钥 |
| Stripe Key | Critical | Stripe支付API密钥 |
| Twilio Key | High | Twilio通信API密钥 |
| SendGrid Key | High | SendGrid邮件API密钥 |
| Slack Token | High | Slack集成令牌 |
| Telegram Token | High | Telegram机器人令牌 |

## 快速开始

### 1. 安装依赖

```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 2. 配置GitHub Token

在GitHub上创建Personal Access Token：

1. 访问 GitHub Settings -> Developer settings -> Personal access tokens
2. 点击 "Generate new token"
3. 选择 `repo` 和 `security_events` 权限
4. 复制生成的token

### 3. 配置环境变量

创建 `.env` 文件：

```env
GITHUB_TOKEN=your_github_token_here

# 邮件通知配置（可选）
SMTP_HOST=smtp.gmail.com
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
```

### 4. 运行扫描

```bash
# 使用默认配置扫描
python main.py scan

# 快速发现候选文件，只保存项目地址和文件地址
python main.py discover --query "sk_live_" --max-results 20

# 默认优先走网页搜索，不占GitHub Search API额度，当前优先 Bing，偏向找 .env / config / secret 线索

# 如需查看文档、测试目录等被排除的搜索结果
python main.py discover --query "sk_live_" --max-results 20 --include-excluded

# 自定义搜索查询
python main.py scan --query "AKIA"

# 限制最大结果数
python main.py scan --max-results 50

# 人工复核后批准某条结果用于通知
python main.py approve reports/scan_report_20240101_120000.json --fingerprint abc123def456

# 只会通知已批准的结果
python main.py notify reports/scan_report_20240101_120000.json
```

## 配置说明

### 基本配置

编辑 `config.yaml` 文件：

```yaml
github:
  token: "${GITHUB_TOKEN}"  # 从环境变量读取
  search:
    max_repositories: 1000
    queries:
      - '"ghp_"'
      - '"github_pat_"'
      - '"sk_live_"'
      - '"AKIA"'
    per_query_limit: 2
    max_candidates_per_query: 5
    per_page: 5
    state_file: "reports/scan_state.json"
    cooldown_days: 30
    languages: []
    time_range_days: 30
```

### 检测配置

```yaml
detection:
  enabled_types:
    - aws_access_key
    - github_token
    - database_url
    # ... 更多类型
  
  false_positive_filters:
    exclude_patterns:
      - "example"
      - "test"
      - "mock"
```

### 通知配置

```yaml
notification:
  require_manual_review: true
  enabled_methods:
    - github_issue
    - email
    - report_only
  
  github_issue:
    title_template: "⚠️ Security Alert: Potential API Key Leak Detected"
    labels:
      - "security"
      - "automated"
```

## GitHub Action集成

### 1. 添加到你的仓库

将 `.github/workflows/scan.yml` 文件添加到你的GitHub仓库。

### 2. 配置Secrets

在仓库的 Settings -> Secrets and variables -> Actions 中添加：

- `KEY_LEAK_DETECTOR`：GitHub Personal Access Token
- `SMTP_HOST`：SMTP服务器地址（可选）
- `SMTP_USER`：SMTP用户名（可选）
- `SMTP_PASSWORD`：SMTP密码（可选）

### 3. 手动触发

在Actions页面，选择 "API Key Leak Scanner" 工作流，点击 "Run workflow"。

### 4. 自动运行

当前工作流默认手动触发。如果需要定时运行，可以在 `.github/workflows/scan.yml` 中添加 `schedule`。

## 命令行工具

### 扫描命令

```bash
# 快速发现候选文件，不拉取文件内容
python main.py discover --query "github_pat_" --max-results 20

# 如果你有自建SearXNG，把 config.yaml 里的 discovery.web_provider 改成 searxng 并填写 web_base_url

# 扫描并生成报告
python main.py scan

# 使用自定义查询
python main.py scan --query "mongodb+srv://"

# 指定最大结果数
python main.py scan --max-results 200
```

### 通知命令

```bash
# 批准单条结果
python main.py approve reports/scan_report_20240101_120000.json --fingerprint abc123def456

# 批准所有 critical 结果
python main.py approve reports/scan_report_20240101_120000.json --all-critical

# 根据报告文件发送通知；未批准的结果只保留为报告，不会主动联系作者
python main.py notify reports/scan_report_20240101_120000.json
```

### 配置检查

```bash
# 检查配置是否正确
python main.py config-check
```

## 项目结构

```
key-leak-detector/
├── .github/
│   └── workflows/
│       └── scan.yml          # GitHub Action配置
├── src/
│   ├── __init__.py
│   ├── github_client.py      # GitHub API客户端
│   ├── key_patterns.py       # 密钥检测模式库
│   ├── scanner.py            # 核心扫描逻辑
│   ├── notifier.py           # 通知模块
│   └── utils.py              # 工具函数
├── tests/
│   ├── __init__.py
│   └── test_scanner.py       # 测试文件
├── reports/                  # 扫描报告目录
├── logs/                     # 日志目录
├── config.yaml               # 配置文件
├── requirements.txt          # Python依赖
├── main.py                   # 主程序入口
└── README.md                 # 项目说明
```

## 安全注意事项

1. **Token安全**：不要将GitHub Token提交到代码仓库
2. **权限最小化**：只授予必要的API权限
3. **定期轮换**：定期更换GitHub Token
4. **监控使用**：监控API使用情况，防止滥用
5. **人工复核**：默认不会自动发送Issue或邮件，必须先批准报告结果
6. **脱敏报告**：报告只保存脱敏内容和指纹，不保存完整密钥

## 误报处理

工具内置了多种误报过滤机制：

- 文件类型过滤（如.md、.txt等）
- 目录过滤（如test、tests等）
- 内容模式过滤（如example、test等）
- 上下文分析

如果发现误报，可以在配置文件中添加排除规则。

## 贡献

欢迎提交Issue和Pull Request！

## 许可证

MIT License

## 免责声明

本工具仅用于安全研究和教育目的。使用本工具时请遵守相关法律法规，不得用于非法用途。作者不对使用本工具造成的任何后果负责。
