"""
GitHub API客户端模块

封装GitHub API调用，提供仓库搜索、文件内容获取、用户信息查询等功能。
"""

import os
import time
from typing import Dict, List, Optional, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

logger = logging.getLogger(__name__)


class GitHubClient:
    """GitHub API客户端"""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: str):
        """
        初始化GitHub客户端
        
        Args:
            token: GitHub Personal Access Token
        """
        self.token = token
        self.session = self._create_session()
        self._setup_rate_limit()
    
    def _create_session(self) -> requests.Session:
        """创建带有重试机制的会话"""
        session = requests.Session()
        
        # 设置认证头
        session.headers.update({
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Key-Leak-Detector/1.0'
        })
        
        # 配置重试策略
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _setup_rate_limit(self):
        """设置速率限制"""
        self.last_request_time = 0
        self.min_request_interval = 1  # 最小请求间隔（秒）
    
    def _wait_for_rate_limit(self, min_interval: float = None):
        """等待速率限制"""
        if min_interval is None:
            min_interval = self.min_request_interval

        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        wait_time = max(0, min_interval - time_since_last_request)
        if wait_time > 0:
            time.sleep(wait_time)
        
        self.last_request_time = time.time()
    
    def search_code(self, query: str, page: int = 1, per_page: int = 100) -> Dict[str, Any]:
        """
        搜索代码
        
        Args:
            query: 搜索查询字符串
            page: 页码
            per_page: 每页结果数
            
        Returns:
            搜索结果
        """
        self._wait_for_rate_limit(6)
        
        url = f"{self.BASE_URL}/search/code"
        params = {
            'q': query,
            'page': page,
            'per_page': per_page
        }
        
        try:
            headers = {
                'Accept': 'application/vnd.github.text-match+json'
            }
            response = self.session.get(url, params=params, headers=headers)
            response.raise_for_status()
            
            # 检查速率限制
            remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            if remaining < 10:
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                wait_time = max(0, reset_time - time.time())
                if wait_time > 0 and wait_time <= 30:
                    logger.warning(f"接近速率限制，等待 {wait_time} 秒")
                    time.sleep(wait_time)
                elif wait_time > 30:
                    logger.warning("接近速率限制，跳过长时间等待，剩余重置时间: %s 秒", int(wait_time))
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"搜索代码失败: {e}")
            raise
    
    def get_file_content(self, repo_name: str, file_path: str, branch: str = None) -> Optional[str]:
        """
        获取文件内容（使用raw.githubusercontent.com，无速率限制）
        
        Args:
            repo_name: 仓库名称（格式：owner/repo）
            file_path: 文件路径
            branch: 分支名称（可选，会自动尝试main和master）
            
        Returns:
            文件内容，如果获取失败返回None
        """
        # 尝试的分支列表。Search API结果通常包含默认分支，优先使用它。
        branches = []
        if branch:
            branches.append(branch)
        branches.extend(['main', 'master'])
        branches = list(dict.fromkeys(branches))
        
        for br in branches:
            raw_url = f"https://raw.githubusercontent.com/{repo_name}/{br}/{file_path}"
            
            try:
                response = requests.get(raw_url, timeout=10)
                
                if response.status_code == 200:
                    return response.text
                    
            except requests.exceptions.RequestException as e:
                logger.debug(f"下载文件失败 {raw_url}: {e}")
                continue
        
        logger.warning(f"无法获取文件内容: {repo_name}/{file_path}")
        return None
    
    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """
        获取用户信息
        
        Args:
            username: GitHub用户名
            
        Returns:
            用户信息字典，如果获取失败返回None
        """
        self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}/users/{username}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"获取用户信息失败: {e}")
            return None
    
    def get_repository_info(self, repo_name: str) -> Optional[Dict[str, Any]]:
        """
        获取仓库信息
        
        Args:
            repo_name: 仓库名称（格式：owner/repo）
            
        Returns:
            仓库信息字典，如果获取失败返回None
        """
        self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}/repos/{repo_name}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"获取仓库信息失败: {e}")
            return None
    
    def create_issue(self, repo_name: str, title: str, body: str, 
                    labels: List[str] = None) -> Optional[Dict[str, Any]]:
        """
        创建GitHub Issue
        
        Args:
            repo_name: 仓库名称（格式：owner/repo）
            title: Issue标题
            body: Issue内容
            labels: 标签列表
            
        Returns:
            创建的Issue信息，如果创建失败返回None
        """
        self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}/repos/{repo_name}/issues"
        
        payload = {
            'title': title,
            'body': body
        }
        
        if labels:
            payload['labels'] = labels
        
        try:
            response = self.session.post(url, json=payload)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"创建Issue失败: {e}")
            return None
    
    def create_comment(self, repo_name: str, issue_number: int, body: str) -> Optional[Dict[str, Any]]:
        """
        在Issue上创建评论
        
        Args:
            repo_name: 仓库名称（格式：owner/repo）
            issue_number: Issue编号
            body: 评论内容
            
        Returns:
            创建的评论信息，如果创建失败返回None
        """
        self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}/repos/{repo_name}/issues/{issue_number}/comments"
        
        payload = {
            'body': body
        }
        
        try:
            response = self.session.post(url, json=payload)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"创建评论失败: {e}")
            return None
    
    def get_commits(self, repo_name: str, path: str = None, 
                   since: str = None, until: str = None) -> List[Dict[str, Any]]:
        """
        获取提交历史
        
        Args:
            repo_name: 仓库名称（格式：owner/repo）
            path: 文件路径（可选）
            since: 起始时间（ISO格式，可选）
            until: 结束时间（ISO格式，可选）
            
        Returns:
            提交列表
        """
        self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}/repos/{repo_name}/commits"
        
        params = {}
        if path:
            params['path'] = path
        if since:
            params['since'] = since
        if until:
            params['until'] = until
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"获取提交历史失败: {e}")
            return []
    
    def get_commit_diff(self, repo_name: str, commit_sha: str) -> Optional[Dict[str, Any]]:
        """
        获取提交差异
        
        Args:
            repo_name: 仓库名称（格式：owner/repo）
            commit_sha: 提交SHA
            
        Returns:
            提交差异信息，如果获取失败返回None
        """
        self._wait_for_rate_limit()
        
        url = f"{self.BASE_URL}/repos/{repo_name}/commits/{commit_sha}"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"获取提交差异失败: {e}")
            return None
