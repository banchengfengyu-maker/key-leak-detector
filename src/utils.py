"""
工具模块

提供配置加载、日志设置等实用功能。
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, Any
import yaml
from dotenv import load_dotenv


def load_config(config_path: str = 'config.yaml') -> Dict[str, Any]:
    """
    加载配置文件
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        配置字典
    """
    # 加载环境变量
    load_dotenv()
    
    # 读取配置文件
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    # 替换环境变量
    config = _replace_env_vars(config)
    
    return config


def _replace_env_vars(obj: Any) -> Any:
    """
    递归替换配置中的环境变量
    
    Args:
        obj: 配置对象
        
    Returns:
        替换后的配置对象
    """
    if isinstance(obj, dict):
        return {key: _replace_env_vars(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_replace_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        # 替换 ${VAR_NAME} 格式的环境变量
        def replace_env(match):
            env_var = match.group(1)
            return os.environ.get(env_var, match.group(0))
        
        return re.sub(r'\$\{(\w+)\}', replace_env, obj)
    else:
        return obj


def setup_logging(logging_config: Dict = None):
    """
    设置日志
    
    Args:
        logging_config: 日志配置字典
    """
    if logging_config is None:
        logging_config = {}
    
    # 默认配置
    log_level = logging_config.get('level', 'INFO')
    log_file = logging_config.get('file', 'logs/key-leak-detector.log')
    max_size_mb = logging_config.get('max_size_mb', 10)
    backup_count = logging_config.get('backup_count', 5)
    
    # 创建日志目录
    log_dir = Path(log_file).parent
    log_dir.mkdir(exist_ok=True)
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # 清除现有处理器
    root_logger.handlers.clear()
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # 文件处理器
    try:
        from logging.handlers import RotatingFileHandler
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
        
    except Exception as e:
        logging.warning(f"无法创建文件日志处理器: {e}")


def sanitize_filename(filename: str) -> str:
    """
    清理文件名，移除不安全字符
    
    Args:
        filename: 原始文件名
        
    Returns:
        清理后的文件名
    """
    # 移除不安全字符
    safe_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # 移除前导和尾随空格
    safe_filename = safe_filename.strip()
    
    # 确保文件名不为空
    if not safe_filename:
        safe_filename = 'unnamed'
    
    return safe_filename


def format_file_size(size_bytes: int) -> str:
    """
    格式化文件大小
    
    Args:
        size_bytes: 文件大小（字节）
        
    Returns:
        格式化后的文件大小字符串
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    截断字符串
    
    Args:
        text: 原始字符串
        max_length: 最大长度
        suffix: 截断后添加的后缀
        
    Returns:
        截断后的字符串
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def validate_github_token(token: str) -> bool:
    """
    验证GitHub Token格式
    
    Args:
        token: GitHub Token
        
    Returns:
        是否有效
    """
    if not token:
        return False
    
    # 检查Token格式
    valid_prefixes = ['ghp_', 'gho_', 'github_pat_']
    
    for prefix in valid_prefixes:
        if token.startswith(prefix):
            return True
    
    # 如果不是标准格式，检查长度
    if len(token) >= 40:
        return True
    
    return False


def get_severity_color(severity: str) -> str:
    """
    获取严重程度对应的颜色
    
    Args:
        severity: 严重程度
        
    Returns:
        颜色代码
    """
    severity_colors = {
        'critical': 'red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'green'
    }
    
    return severity_colors.get(severity, 'white')