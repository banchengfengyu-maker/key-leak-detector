"""
核心扫描逻辑模块

实现GitHub仓库扫描、误报过滤等功能。
"""

import hashlib
import json
import re
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from pathlib import Path

from .github_client import GitHubClient
from .key_patterns import PatternMatcher, KeyPatterns
from .web_discovery import WebDiscoveryClient

logger = logging.getLogger(__name__)


DEFAULT_SEARCH_QUERIES = [
    '.env github',
    'config github secret',
    'credentials github',
]


class ScanState:
    """轻量级扫描状态，用于续扫、去重和冷却。"""

    def __init__(self, state_file: str, cooldown_days: int = 30):
        self.state_file = Path(state_file)
        self.cooldown_days = cooldown_days
        self.data = self._load()

    def _load(self) -> Dict:
        if not self.state_file.exists():
            return {'queries': {}, 'findings': {}}

        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            logger.warning("扫描状态文件不可读，将重新开始: %s", self.state_file)
            return {'queries': {}, 'findings': {}}

        data.setdefault('queries', {})
        data.setdefault('findings', {})
        return data

    def save(self):
        self.state_file.parent.mkdir(exist_ok=True)
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

    def get_page(self, query: str) -> int:
        return int(self.data['queries'].get(query, {}).get('next_page', 1))

    def set_page(self, query: str, page: int):
        self.data['queries'][query] = {
            'next_page': max(1, page),
            'updated_at': datetime.now().isoformat()
        }

    def is_recent_finding(self, fingerprint: str) -> bool:
        seen_at = self.data['findings'].get(fingerprint)
        if not seen_at:
            return False

        try:
            seen_time = datetime.fromisoformat(seen_at)
        except ValueError:
            return False

        return datetime.now() - seen_time < timedelta(days=self.cooldown_days)

    def mark_finding(self, fingerprint: str):
        self.data['findings'][fingerprint] = datetime.now().isoformat()


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
        self.search_queries = search_config.get('queries') or DEFAULT_SEARCH_QUERIES
        self.per_query_limit = int(search_config.get('per_query_limit', 10))
        self.max_candidates_per_query = int(search_config.get('max_candidates_per_query', 20))
        self.per_page = int(search_config.get('per_page', 10))
        self.use_text_matches = bool(search_config.get('use_text_matches', True))
        self.fetch_metadata = bool(search_config.get('fetch_metadata', False))
        self.discovery_client = WebDiscoveryClient(config)
        self.state = ScanState(
            search_config.get('state_file', 'reports/scan_state.json'),
            int(search_config.get('cooldown_days', 30))
        )
    
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
        
        results = []
        queries = [query] if query else self.search_queries

        for current_query in queries:
            if len(results) >= max_results:
                break

            logger.info("搜索查询: %s", current_query)
            page = self.state.get_page(current_query)
            per_page = max(1, min(100, self.per_page))
            query_results = 0
            processed_candidates = 0

            while (
                len(results) < max_results
                and query_results < self.per_query_limit
                and processed_candidates < self.max_candidates_per_query
            ):
                try:
                    search_results = self.github_client.search_code(
                        current_query,
                        page=page,
                        per_page=per_page
                    )

                    if not search_results.get('items'):
                        self.state.set_page(current_query, 1)
                        break

                    for item in search_results['items']:
                        if (
                            len(results) >= max_results
                            or query_results >= self.per_query_limit
                            or processed_candidates >= self.max_candidates_per_query
                        ):
                            break

                        processed_candidates += 1
                        item_results = self._process_search_item(item)
                        for result in item_results:
                            if len(results) >= max_results or query_results >= self.per_query_limit:
                                break

                            fingerprint = result['fingerprint']
                            if self.state.is_recent_finding(fingerprint):
                                logger.info("跳过冷却期内的重复发现: %s", fingerprint)
                                continue

                            self.state.mark_finding(fingerprint)
                            results.append(result)
                            query_results += 1

                    total_count = min(search_results.get('total_count', 0), 1000)
                    next_page = page + 1
                    if page * per_page >= total_count:
                        next_page = 1
                    self.state.set_page(current_query, next_page)
                    page = next_page

                    # 避免触发速率限制
                    time.sleep(0.1)

                    if page == 1:
                        break

                except Exception as e:
                    logger.error(f"扫描过程中发生错误: {e}")
                    break

            try:
                self.state.save()
            except OSError as e:
                logger.warning("保存扫描状态失败: %s", e)
        
        logger.info(f"扫描完成，发现 {len(results)} 个潜在泄露")
        return results

    def discover_candidates(self, query: str = None, max_results: int = 50,
                            include_excluded: bool = False) -> List[Dict]:
        """
        快速发现候选文件，只保存GitHub Search返回的仓库和文件地址。

        这个阶段不拉取raw文件、不查询作者详情、不保存text_matches片段。
        """
        logger.info("开始快速发现候选文件")

        candidates = []
        seen = set()
        queries = [query] if query else self.search_queries

        web_max_results = max_results

        for current_query in queries:
            if len(candidates) >= max_results:
                break

            logger.info("网页候选查询: %s", current_query)
            try:
                web_candidates = self.discovery_client.search(current_query, max_results=web_max_results)
            except Exception as exc:
                logger.error("网页发现失败: %s", exc)
                web_candidates = []

            for candidate in web_candidates:
                if len(candidates) >= max_results:
                    break

                if not include_excluded and self._is_excluded_candidate(candidate):
                    continue

                fingerprint = candidate['candidate_fingerprint']
                if fingerprint in seen:
                    continue

                candidate['source_query'] = current_query
                seen.add(fingerprint)
                candidates.append(candidate)

        logger.info("候选发现完成，发现 %s 个候选文件", len(candidates))
        return candidates
    
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
    
    def _process_search_item(self, item: Dict) -> List[Dict]:
        """
        处理搜索结果项
        
        Args:
            item: 搜索结果项
            
        Returns:
            处理后的结果，如果为误报返回None
        """
        try:
            text_match_content = self._extract_text_matches(item)
            if self.use_text_matches and text_match_content:
                logger.debug(
                    "收到 text_matches 片段，继续拉取完整文件复核: %s",
                    item.get('html_url', '')
                )

            # 获取文件内容
            repo_name = item['repository']['full_name']
            file_path = item['path']
            branch = item['repository'].get('default_branch')
            
            content = self.github_client.get_file_content(repo_name, file_path, branch=branch)
            if not content:
                return []
            
            # 查找密钥
            found_keys = self.pattern_matcher.find_keys(content)
            
            # 过滤误报
            valid_keys = []
            for key_info in found_keys:
                if not self.false_positive_filter.is_false_positive(file_path, content, key_info):
                    valid_keys.append(key_info)
            
            if not valid_keys:
                return []
            
            # 扫描阶段默认不额外查用户/仓库详情，避免触发GitHub二级限流。
            author_info = self._get_author_info(repo_name, item) if self.fetch_metadata else self._basic_author_info(item)
            repo_info = self.github_client.get_repository_info(repo_name) if self.fetch_metadata else None
            
            # 构建结果
            results = []
            for key_info in valid_keys:
                result = self._build_result(item, repo_name, file_path, key_info, author_info, repo_info)
                results.append(result)

            return results
            
        except Exception as e:
            logger.error(f"处理搜索结果项失败: {e}")
            return []

    def _extract_text_matches(self, item: Dict) -> str:
        """提取 GitHub Search API 返回的匹配片段。"""
        fragments = []
        for match in item.get('text_matches', []) or []:
            fragment = match.get('fragment')
            if fragment:
                fragments.append(fragment)
        return '\n'.join(fragments)

    def _build_candidate(self, item: Dict, query: str) -> Dict:
        """构建不含密钥内容的候选记录。"""
        repo = item['repository']
        owner = repo['owner']
        repo_name = repo['full_name']
        file_path = item['path']
        payload = f"{repo_name}\0{file_path}\0{query}".encode('utf-8', errors='replace')

        return {
            'candidate_only': True,
            'repo_name': repo_name,
            'repo_url': repo['html_url'],
            'owner_username': owner.get('login', ''),
            'owner_profile_url': owner.get('html_url', ''),
            'file_path': file_path,
            'file_url': item['html_url'],
            'source_query': query,
            'text_match_count': len(item.get('text_matches', []) or []),
            'candidate_fingerprint': hashlib.sha256(payload).hexdigest(),
            'approved_for_notification': False,
            'source_kind': 'github_search',
            'timestamp': datetime.now().isoformat()
        }

    def _is_excluded_candidate(self, item: Dict) -> bool:
        """候选发现阶段复用文件/目录排除规则。"""
        file_path = item.get('path') or item.get('file_path') or ''
        return (
            self.false_positive_filter._is_excluded_file(file_path)
            or self.false_positive_filter._is_excluded_dir(file_path)
        )

    def _build_result(self, item: Dict, repo_name: str, file_path: str, key_info: Dict,
                      author_info: Dict, repo_info: Optional[Dict]) -> Dict:
        """构建脱敏后的扫描结果。"""
        raw_content = key_info['content']
        masked_content = self._mask_secret(raw_content)
        masked_context = key_info.get('context', '').replace(raw_content, masked_content)
        fingerprint = self._fingerprint(repo_name, file_path, key_info['key_type'], raw_content)

        return {
            'repo_name': repo_name,
            'repo_url': item['repository']['html_url'],
            'file_path': file_path,
            'file_url': item['html_url'],
            'line_number': key_info['line_number'],
            'key_type': key_info['key_type'],
            'description': key_info['description'],
            'severity': key_info['severity'],
            'content': masked_content,
            'context': masked_context,
            'fingerprint': fingerprint,
            'approved_for_notification': False,
            'author': author_info,
            'repository': repo_info,
            'timestamp': datetime.now().isoformat()
        }

    def _fingerprint(self, repo_name: str, file_path: str, key_type: str, secret: str) -> str:
        """生成不暴露密钥内容的稳定指纹。"""
        payload = f"{repo_name}\0{file_path}\0{key_type}\0{secret}".encode('utf-8', errors='replace')
        return hashlib.sha256(payload).hexdigest()

    def _mask_secret(self, secret: str) -> str:
        """脱敏展示疑似密钥，报告中不保存完整密钥。"""
        compact = secret.strip()
        if len(compact) <= 8:
            return '*' * len(compact)
        if len(compact) <= 16:
            return f"{compact[:3]}...{compact[-3:]}"
        return f"{compact[:6]}...{compact[-4:]}"

    def _basic_author_info(self, item: Dict) -> Dict:
        """从搜索结果中提取基础作者信息，不发起额外API请求。"""
        owner = item['repository']['owner']
        return {
            'username': owner.get('login', ''),
            'name': '',
            'email': '',
            'bio': '',
            'profile_url': owner.get('html_url', ''),
            'avatar_url': owner.get('avatar_url', '')
        }
    
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
