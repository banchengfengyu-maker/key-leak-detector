"""
密钥检测正则表达式模式库

定义各种API密钥和敏感信息的检测模式。
"""

import re
from typing import Dict, List, Tuple


class KeyPattern:
    """密钥模式定义"""
    
    def __init__(self, name: str, pattern: str, description: str, 
                 severity: str = "high", examples: List[str] = None):
        """
        初始化密钥模式
        
        Args:
            name: 模式名称
            pattern: 正则表达式模式
            description: 描述
            severity: 严重程度 (low, medium, high, critical)
            examples: 示例列表
        """
        self.name = name
        self.pattern = pattern
        self.description = description
        self.severity = severity
        self.examples = examples or []
        self.compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    
    def match(self, text: str) -> List[Tuple[str, int, int]]:
        """
        在文本中匹配模式
        
        Args:
            text: 要匹配的文本
            
        Returns:
            匹配结果列表，每个元素为 (匹配内容, 起始位置, 结束位置)
        """
        matches = []
        for match in self.compiled_pattern.finditer(text):
            matches.append((match.group(), match.start(), match.end()))
        return matches


class KeyPatterns:
    """密钥模式管理器"""
    
    # AWS密钥模式
    AWS_ACCESS_KEY = KeyPattern(
        name="aws_access_key",
        pattern=r'AKIA[0-9A-Z]{16}',
        description="AWS Access Key ID",
        severity="critical",
        examples=[
            "AKIASAMPLE1234567890",
            "AKIAIOSFODNN7EXAMPLE"
        ]
    )
    
    AWS_SECRET_KEY = KeyPattern(
        name="aws_secret_key",
        pattern=r'(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        description="AWS Secret Access Key",
        severity="critical",
        examples=[
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ]
    )
    
    AWS_SESSION_TOKEN = KeyPattern(
        name="aws_session_token",
        pattern=r'(?i)(?:aws_session_token|session_token)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
        description="AWS Session Token",
        severity="high",
        examples=[
            "aws_session_token = FwoGZXIvYXdzEBY..."
        ]
    )
    
    # Azure密钥模式
    AZURE_STORAGE_KEY = KeyPattern(
        name="azure_storage_key",
        pattern=r'(?i)(?:account_key|storage_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{86,})["\']?',
        description="Azure Storage Account Key",
        severity="critical",
        examples=[
            "account_key = EjZ5..."
        ]
    )
    
    AZURE_CLIENT_SECRET = KeyPattern(
        name="azure_client_secret",
        pattern=r'(?i)(?:client_secret|azure_client_secret)\s*[=:]\s*["\']?([A-Za-z0-9._~-]{34,})["\']?',
        description="Azure Client Secret",
        severity="critical",
        examples=[
            "client_secret = abc123..."
        ]
    )
    
    # Google Cloud Platform密钥模式
    GCP_API_KEY = KeyPattern(
        name="gcp_api_key",
        pattern=r'(?i)(?:api_key|apikey|google_api_key)\s*[=:]\s*["\']?([A-Za-z0-9_-]{35})["\']?',
        description="Google Cloud API Key",
        severity="critical",
        examples=[
            "api_key = AIzaSyDSAMPLE123456789012345678901"
        ]
    )
    
    GCP_SERVICE_ACCOUNT = KeyPattern(
        name="gcp_service_account",
        pattern=r'(?i)(?:service_account|gcp_service_account)\s*[=:]\s*["\']?(\{[^}]+\})["\']?',
        description="Google Cloud Service Account Key",
        severity="critical",
        examples=[
            'service_account = {"type": "service_account", ...}'
        ]
    )
    
    # GitHub令牌模式
    GITHUB_TOKEN = KeyPattern(
        name="github_token",
        pattern=r'(?i)(?:(?:github_token|gh_token|access_token)\s*[=:]\s*["\']?)?(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})',
        description="GitHub Personal Access Token",
        severity="critical",
        examples=[
            "github_token = ghp_SAMPLE123456789012345678901234567890",
            "gh_token = gho_SAMPLE123456789012345678901234567890"
        ]
    )
    
    GITHUB_OAUTH = KeyPattern(
        name="github_oauth",
        pattern=r'(?i)(?:github_oauth|oauth_token)\s*[=:]\s*["\']?(gho_[A-Za-z0-9]{36})["\']?',
        description="GitHub OAuth Token",
        severity="critical",
        examples=[
            "github_oauth = gho_SAMPLE123456789012345678901234567890"
        ]
    )
    
    # 数据库连接字符串模式
    DATABASE_URL = KeyPattern(
        name="database_url",
        pattern=r'(?i)(?:database_url|db_url|connection_string)\s*[=:]\s*["\']?((?:mysql|postgresql|mongodb|redis|sqlite)://[^\s"\']+)',
        description="Database Connection URL",
        severity="critical",
        examples=[
            "database_url = mysql://user:password@host:3306/dbname",
            "db_url = postgresql://user:password@host:5432/dbname"
        ]
    )
    
    MONGODB_URL = KeyPattern(
        name="mongodb_url",
        pattern=r'(?i)(?:mongodb_url|mongo_url)\s*[=:]\s*["\']?(mongodb(\+srv)?://[^\s"\']+)',
        description="MongoDB Connection URL",
        severity="critical",
        examples=[
            "mongodb_url = mongodb+srv://user:password@cluster.mongodb.net/dbname"
        ]
    )
    
    REDIS_URL = KeyPattern(
        name="redis_url",
        pattern=r'(?i)(?:redis_url|redis_connection)\s*[=:]\s*["\']?(redis://[^\s"\']+)',
        description="Redis Connection URL",
        severity="high",
        examples=[
            "redis_url = redis://user:password@host:6379/0"
        ]
    )
    
    # 私钥模式
    PRIVATE_KEY = KeyPattern(
        name="private_key",
        pattern=r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        description="Private Key",
        severity="critical",
        examples=[
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----"
        ]
    )
    
    # 第三方服务密钥模式
    STRIPE_KEY = KeyPattern(
        name="stripe_key",
        pattern=r'(?i)(?:(?:stripe_key|stripe_secret|stripe_api_key)\s*[=:]\s*["\']?)?(sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,})',
        description="Stripe API Key",
        severity="critical",
        examples=[
            "stripe_key = sk_live_SAMPLE1234567890123456",
            "stripe_secret = sk_test_SAMPLE1234567890123456"
        ]
    )
    
    TWILIO_KEY = KeyPattern(
        name="twilio_key",
        pattern=r'(?i)(?:twilio_key|twilio_auth_token|twilio_api_key)\s*[=:]\s*["\']?([A-Za-z0-9]{32})["\']?',
        description="Twilio API Key",
        severity="high",
        examples=[
            "twilio_key = SAMPLE1234567890123456789012"
        ]
    )
    
    SENDGRID_KEY = KeyPattern(
        name="sendgrid_key",
        pattern=r'(?i)(?:sendgrid_key|sendgrid_api_key|sendgrid)\s*[=:]\s*["\']?(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})["\']?',
        description="SendGrid API Key",
        severity="high",
        examples=[
            "sendgrid_key = SG.SAMPLE12345678901234.SAMPLE1234567890123456789012345678901234567890"
        ]
    )
    
    MAILGUN_KEY = KeyPattern(
        name="mailgun_key",
        pattern=r'(?i)(?:mailgun_key|mailgun_api_key)\s*[=:]\s*["\']?(key-[A-Za-z0-9]{32})["\']?',
        description="Mailgun API Key",
        severity="high",
        examples=[
            "mailgun_key = key-abc123def456ghi789jkl012mno345pqr"
        ]
    )
    
    SLACK_TOKEN = KeyPattern(
        name="slack_token",
        pattern=r'(?i)(?:slack_token|slack_api_token)\s*[=:]\s*["\']?(xox[baprs]-[A-Za-z0-9-]+)["\']?',
        description="Slack Token",
        severity="high",
        examples=[
            "slack_token = xoxb-SAMPLE123456-SAMPLE1234567890-SAMPLE1234567890"
        ]
    )
    
    TELEGRAM_TOKEN = KeyPattern(
        name="telegram_token",
        pattern=r'(?i)(?:telegram_token|telegram_bot_token|tg_token)\s*[=:]\s*["\']?(\d{9,}:[A-Za-z0-9_-]{35})["\']?',
        description="Telegram Bot Token",
        severity="high",
        examples=[
            "telegram_token = 1234567890:SAMPLE1234567890123456789012345678"
        ]
    )
    
    # 通用API密钥模式
    GENERIC_API_KEY = KeyPattern(
        name="generic_api_key",
        pattern=r'(?i)(?:api_key|apikey|api_secret|access_key|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9]{20,})["\']?',
        description="Generic API Key",
        severity="medium",
        examples=[
            "api_key = abcdef1234567890abcdef",
            "apikey = 1234567890abcdef12345678"
        ]
    )
    
    GENERIC_SECRET = KeyPattern(
        name="generic_secret",
        pattern=r'(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?',
        description="Generic Secret/Password",
        severity="medium",
        examples=[
            "secret = mysecretpassword123",
            "password = password123"
        ]
    )
    
    # 配置文件中的敏感信息
    ENV_FILE_SECRET = KeyPattern(
        name="env_file_secret",
        pattern=r'(?i)(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)[\s_]*[=:]\s*["\']?([^\s"\']+)["\']?',
        description="Environment Variable Secret",
        severity="high",
        examples=[
            "SECRET_KEY = abcdef1234567890",
            "PASSWORD = mysecretpassword"
        ]
    )
    
    @classmethod
    def get_all_patterns(cls) -> List[KeyPattern]:
        """
        获取所有密钥模式
        
        Returns:
            所有密钥模式列表
        """
        patterns = []
        for attr_name in dir(cls):
            attr_value = getattr(cls, attr_name)
            if isinstance(attr_value, KeyPattern):
                patterns.append(attr_value)
        return patterns
    
    @classmethod
    def get_pattern_by_name(cls, name: str) -> KeyPattern:
        """
        根据名称获取密钥模式
        
        Args:
            name: 模式名称
            
        Returns:
            对应的密钥模式
        """
        for pattern in cls.get_all_patterns():
            if pattern.name == name:
                return pattern
        raise ValueError(f"未找到模式: {name}")
    
    @classmethod
    def get_patterns_by_severity(cls, severity: str) -> List[KeyPattern]:
        """
        根据严重程度获取密钥模式
        
        Args:
            severity: 严重程度
            
        Returns:
            对应的密钥模式列表
        """
        return [p for p in cls.get_all_patterns() if p.severity == severity]


class PatternMatcher:
    """模式匹配器"""
    
    def __init__(self, enabled_types: List[str] = None):
        """
        初始化模式匹配器
        
        Args:
            enabled_types: 启用的密钥类型列表
        """
        if enabled_types:
            self.patterns = [KeyPatterns.get_pattern_by_name(t) for t in enabled_types]
        else:
            self.patterns = KeyPatterns.get_all_patterns()
    
    def find_keys(self, text: str) -> List[Dict]:
        """
        在文本中查找所有密钥
        
        Args:
            text: 要搜索的文本
            
        Returns:
            找到的密钥列表
        """
        found_keys = []
        
        for pattern in self.patterns:
            matches = pattern.match(text)
            
            for match_content, start, end in matches:
                # 计算行号
                line_number = text[:start].count('\n') + 1
                
                # 获取上下文
                context_start = max(0, start - 50)
                context_end = min(len(text), end + 50)
                context = text[context_start:context_end]
                
                found_keys.append({
                    'key_type': pattern.name,
                    'description': pattern.description,
                    'severity': pattern.severity,
                    'content': match_content,
                    'line_number': line_number,
                    'start_position': start,
                    'end_position': end,
                    'context': context
                })
        
        return found_keys
