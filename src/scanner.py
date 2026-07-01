"""
核心扫描逻辑模块

实现GitHub仓库扫描、误报过滤等功能。
"""

import re
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from pathlib import Path

from .github_client import GitHubClient
from .key_patterns import PatternMatcher, KeyPatterns

logger = logging.getLogger(__name__)


class FalsePositiveFilter:
    """误报过滤器"""
    
    def __init__(self, config: Dict):
        """
        初始化误报过滤器
        
        Args:
            config: 配置字典
        """
        self.config = config.get('detection', {}).get('false_positive_filters', {})
        
        # 编译排除模式
        exclude_patterns = self.config.get('exclude_patterns', [])
        self.exclude_patterns = [re.compile(p, re.IGNORECASE) for p in exclude_patterns]
        
        # 排除文件列表
        self.exclude_files = self.config.get('exclude_files', [])
        
        # 排除目录列表
        self.exclude_dirs = self.config.get('exclude_dirs', [])
    
    def is_false_positive(self, file_path: str, content: str, key_info: Dict) -> bool:
        """
        检查是否为误报
        
        Args:
            file_path: 文件路径
            content: 文件内容
            key_info: 密钥信息
            
        Returns:
            是否为误报
        """
        # 检查文件路径
        if self._is_excluded_file(file_path):
            return True
        
        # 检查目录
        if self._is_excluded_dir(file_path):
            return True
        
        # 检查匹配内容
        if self._is_excluded_content(key_info.get('content', '')):
            return True
        
        # 检查上下文
        if self._is_excluded_context(key_info.get('context', '')):
            return True
        
        # 检查是否为示例或测试代码
        if self._is_example_or_test(content, key_info):
            return True
        
        return False
    
    def _is_excluded_file(self, file_path: str) -> bool:
        """检查是否为排除的文件"""
        from pathlib import PurePath
        
        file_name = PurePath(file_path).name
        
        for pattern in self.exclude_files:
            if PurePath(file_name).match(pattern):
                return True
        
        return False
    
    def _is_excluded_dir(self, file_path: str) -> bool:
        """检查是否在排除的目录中"""
        path_parts = Path(file_path).parts
        
        for excluded_dir in self.exclude_dirs:
            if excluded_dir in path_parts:
                return True
        
        return False
    
    def _is_excluded_content(self, content: str) -> bool:
        """检查内容是否匹配排除模式"""
        for pattern in self.exclude_patterns:
            if pattern.search(content):
                return True
        
        return False
    
    def _is_excluded_context(self, context: str) -> bool:
        """检查上下文是否包含排除模式"""
        for pattern in self.exclude_patterns:
            if pattern.search(context):
                return True
        
        return False
    
    def _is_example_or_test(self, content: str, key_info: Dict) -> bool:
        """检查是否为示例或测试代码"""
        # 检查常见示例关键词
        example_patterns = [
            r'example',
            r'test',
            r'mock',
            r'fake',
            r'dummy',
            r'placeholder',
            r'sample',
            r'demo',
            r'tutorial',
            r'documentation',
        ]
        
        for pattern in example_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # 检查是否在注释或字符串中
                line_number = key_info.get('line_number', 0)
                lines = content.split('\n')
                
                if 0 <= line_number - 1 < len(lines):
                    line = lines[line_number - 1]
                    
                    # 检查是否在注释中
                    if re.search(r'//.*|/\*.*\*/|#.*', line):
                        return True
        
        return False


class Scanner:
    """扫描器主类"""
    
    def __init__(self, config: Dict):
        """
        初始化扫描器
        
        Args:
            config: 配置字典
        """
        self.config = config
        self.github_client = GitHubClient(config['github']['token'])
        self.pattern_matcher = PatternMatcher(
            config.get('detection', {}).get('enabled_types')
        )
        self.false_positive_filter = FalsePositiveFilter(config)
        
        # 搜索配置
        search_config = config.get('github', {}).get('search', {})
        self.max_repositories = search_config.get('max_repositories', 1000)
        self.languages = search_config.get('languages', [])
        self.time_range_days = search_config.get('time_range_days', 30)
    
    def scan(self, query: str = None, max_results: int = 100) -> List[Dict]:
        """
        执行扫描
        
        Args:
            query: 自定义搜索查询
            max_results: 最大结果数
            
        Returns:
            扫描结果列表
        """
        logger.info("开始扫描API密钥泄露")
        
        # 构建搜索查询
        if not query:
            query = self._build_search_query()
        
        logger.info(f"搜索查询: {query}")
        
        results = []
        page = 1
        per_page = min(100, max_results)
        
        while len(results) < max_results:
            try:
                # 搜索代码
                search_results = self.github_client.search_code(query, page=page, per_page=per_page)
                
                if not search_results.get('items'):
                    break
                
                # 处理搜索结果
                for item in search_results['items']:
                    if len(results) >= max_results:
                        break
                    
                    result = self._process_search_item(item)
                    if result:
                        results.append(result)
                
                # 检查是否还有更多结果
                total_count = search_results.get('total_count', 0)
                if page * per_page >= total_count:
                    break
                
                page += 1
                
                # 避免触发速率限制
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"扫描过程中发生错误: {e}")
                break
        
        logger.info(f"扫描完成，发现 {len(results)} 个潜在泄露")
        return results
    
    def _build_search_query(self) -> str:
        """构建搜索查询字符串"""
        # 基础查询
        queries = []
        
        # 添加密钥模式搜索
        key_patterns = [
            "AKIA",  # AWS Access Key
            "ghp_",  # GitHub Personal Access Token
            "gho_",  # GitHub OAuth Token
            "github_pat_",  # GitHub Fine-grained Personal Access Token
            "sk_live_",  # Stripe Live Secret Key
            "sk_test_",  # Stripe Test Secret Key
            "SG.",  # SendGrid API Key
            "mongodb+srv://",  # MongoDB Atlas
            "mysql://",  # MySQL
            "postgresql://",  # PostgreSQL
            "redis://",  # Redis
            "-----BEGIN.*PRIVATE KEY",  # Private Keys
        ]
        
        # 构建查询
        for pattern in key_patterns:
            queries.append(f'"{pattern}"')
        
        query = " OR ".join(queries)
        
        # 添加语言过滤
        if self.languages:
            lang_query = " ".join([f"language:{lang}" for lang in self.languages])
            query += f" {lang_query}"
        
        # 添加时间范围过滤
        if self.time_range_days:
            date = (datetime.now() - timedelta(days=self.time_range_days)).strftime("%Y-%m-%d")
            query += f" created:>{date}"
        
        return query
    
    def _process_search_item(self, item: Dict) -> Optional[Dict]:
        """
        处理搜索结果项
        
        Args:
            item: 搜索结果项
            
        Returns:
            处理后的结果，如果为误报返回None
        """
        try:
            # 获取文件内容
            repo_name = item['repository']['full_name']
            file_path = item['path']
            
            content = self.github_client.get_file_content(repo_name, file_path)
            if not content:
                return None
            
            # 查找密钥
            found_keys = self.pattern_matcher.find_keys(content)
            
            # 过滤误报
            valid_keys = []
            for key_info in found_keys:
                if not self.false_positive_filter.is_false_positive(file_path, content, key_info):
                    valid_keys.append(key_info)
            
            if not valid_keys:
                return None
            
            # 获取作者信息
            author_info = self._get_author_info(repo_name, item)
            
            # 获取仓库信息
            repo_info = self.github_client.get_repository_info(repo_name)
            
            # 构建结果
            results = []
            for key_info in valid_keys:
                result = {
                    'repo_name': repo_name,
                    'repo_url': item['repository']['html_url'],
                    'file_path': file_path,
                    'file_url': item['html_url'],
                    'line_number': key_info['line_number'],
                    'key_type': key_info['key_type'],
                    'description': key_info['description'],
                    'severity': key_info['severity'],
                    'content': key_info['content'][:50] + '...' if len(key_info['content']) > 50 else key_info['content'],
                    'context': key_info['context'],
                    'author': author_info,
                    'repository': repo_info,
                    'timestamp': datetime.now().isoformat()
                }
                results.append(result)
            
            # 返回第一个结果（避免重复）
            return results[0] if results else None
            
        except Exception as e:
            logger.error(f"处理搜索结果项失败: {e}")
            return None
    
    def _get_author_info(self, repo_name: str, item: Dict) -> Dict:
        """
        获取作者信息
        
        Args:
            repo_name: 仓库名称
            item: 搜索结果项
            
        Returns:
            作者信息字典
        """
        try:
            # 从仓库信息获取作者
            repo_info = self.github_client.get_repository_info(repo_name)
            
            if repo_info and 'owner' in repo_info:
                owner = repo_info['owner']
                
                # 获取用户详细信息
                user_info = self.github_client.get_user_info(owner['login'])
                
                if user_info:
                    return {
                        'username': owner['login'],
                        'name': user_info.get('name', ''),
                        'email': user_info.get('email', ''),
                        'bio': user_info.get('bio', ''),
                        'profile_url': user_info.get('html_url', ''),
                        'avatar_url': user_info.get('avatar_url', '')
                    }
            
            # 如果获取失败，返回基本信息
            return {
                'username': item['repository']['owner']['login'],
                'name': '',
                'email': '',
                'bio': '',
                'profile_url': item['repository']['owner']['html_url'],
                'avatar_url': item['repository']['owner']['avatar_url']
            }
            
        except Exception as e:
            logger.error(f"获取作者信息失败: {e}")
            return {
                'username': item['repository']['owner']['login'],
                'name': '',
                'email': '',
                'bio': '',
                'profile_url': item['repository']['owner']['html_url'],
                'avatar_url': item['repository']['owner']['avatar_url']
            }