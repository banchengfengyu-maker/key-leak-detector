"""
通知模块

实现各种通知方式，包括GitHub Issue、邮件通知等。
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

from .github_client import GitHubClient

logger = logging.getLogger(__name__)


class Notifier:
    """通知器主类"""
    
    def __init__(self, config: Dict):
        """
        初始化通知器
        
        Args:
            config: 配置字典
        """
        self.config = config
        self.notification_config = config.get('notification', {})
        self.enabled_methods = self.notification_config.get('enabled_methods', [])
        self.require_manual_review = self.notification_config.get('require_manual_review', True)
        
        # 初始化GitHub客户端
        self.github_client = GitHubClient(config['github']['token'])
    
    def notify_all(self, results: List[Dict]) -> int:
        """
        发送所有通知
        
        Args:
            results: 扫描结果列表
            
        Returns:
            成功发送的通知数量
        """
        notified_count = 0
        
        for result in results:
            try:
                if self.require_manual_review and not result.get('approved_for_notification'):
                    logger.info(
                        "结果未通过人工批准，跳过主动通知: %s/%s",
                        result.get('repo_name', ''),
                        result.get('file_path', '')
                    )
                    if 'report_only' in self.enabled_methods:
                        notified_count += 1
                    continue

                # GitHub Issue通知
                if 'github_issue' in self.enabled_methods:
                    if self.notify_github_issue(result):
                        notified_count += 1
                
                # 邮件通知
                if 'email' in self.enabled_methods:
                    if self.notify_email(result):
                        notified_count += 1
                
                # 仅报告模式
                if 'report_only' in self.enabled_methods:
                    notified_count += 1
                    
            except Exception as e:
                logger.error(f"发送通知失败: {e}")
        
        return notified_count
    
    def notify_github_issue(self, result: Dict) -> bool:
        """
        通过GitHub Issue发送通知
        
        Args:
            result: 扫描结果
            
        Returns:
            是否发送成功
        """
        try:
            repo_name = result['repo_name']
            
            # 检查是否已经创建过类似的Issue
            if self._issue_already_exists(repo_name, result):
                logger.info(f"仓库 {repo_name} 已有类似Issue，跳过")
                return False
            
            # 准备Issue内容
            issue_config = self.notification_config.get('github_issue', {})
            
            title = self._format_template(
                issue_config.get('title_template', 'Security Alert: Potential API Key Leak Detected'),
                result
            )
            
            body = self._format_template(
                issue_config.get('content_template', ''),
                result
            )
            
            labels = issue_config.get('labels', ['security', 'leak-detected', 'automated'])
            
            # 创建Issue
            issue = self.github_client.create_issue(
                repo_name=repo_name,
                title=title,
                body=body,
                labels=labels
            )
            
            if issue:
                logger.info(f"成功创建Issue: {issue.get('html_url', '')}")
                return True
            else:
                logger.warning(f"创建Issue失败: {repo_name}")
                return False
                
        except Exception as e:
            logger.error(f"发送GitHub Issue通知失败: {e}")
            return False
    
    def notify_email(self, result: Dict) -> bool:
        """
        通过邮件发送通知
        
        Args:
            result: 扫描结果
            
        Returns:
            是否发送成功
        """
        try:
            # 检查是否有邮箱地址
            author_email = result.get('author', {}).get('email', '')
            
            if not author_email:
                logger.info("作者未公开邮箱，跳过邮件通知")
                return False
            
            # 检查邮箱配置
            email_config = self.notification_config.get('email', {})
            smtp_host = email_config.get('smtp_host', '')
            smtp_user = email_config.get('smtp_user', '')
            smtp_password = email_config.get('smtp_password', '')
            
            if not all([smtp_host, smtp_user, smtp_password]):
                logger.warning("邮件配置不完整，跳过邮件通知")
                return False
            
            # 准备邮件内容
            subject = self._format_template(
                email_config.get('subject_template', 'Security Alert: Potential API Key Leak'),
                result
            )
            
            body = self._format_template(
                email_config.get('content_template', ''),
                result
            )
            
            # 发送邮件
            success = self._send_email(
                to_email=author_email,
                subject=subject,
                body=body,
                smtp_config=email_config
            )
            
            if success:
                logger.info(f"成功发送邮件到: {author_email}")
            else:
                logger.warning(f"发送邮件失败: {author_email}")
            
            return success
            
        except Exception as e:
            logger.error(f"发送邮件通知失败: {e}")
            return False
    
    def _issue_already_exists(self, repo_name: str, result: Dict) -> bool:
        """
        检查是否已经存在类似的Issue
        
        Args:
            repo_name: 仓库名称
            result: 扫描结果
            
        Returns:
            是否已存在
        """
        try:
            # 搜索现有的Issues
            search_query = f'"{result["key_type"]}" in:title repo:{repo_name}'
            
            # 这里可以添加更复杂的逻辑来检查是否已存在类似的Issue
            # 目前简单返回False
            return False
            
        except Exception as e:
            logger.error(f"检查Issue是否存在失败: {e}")
            return False
    
    def _format_template(self, template: str, data: Dict) -> str:
        """
        格式化模板
        
        Args:
            template: 模板字符串
            data: 数据字典
            
        Returns:
            格式化后的字符串
        """
        if not template:
            return ""
        
        # 准备模板变量
        template_vars = {
            'repo_name': data.get('repo_name', ''),
            'repo_url': data.get('repo_url', ''),
            'file_path': data.get('file_path', ''),
            'line_number': data.get('line_number', ''),
            'key_type': data.get('key_type', ''),
            'description': data.get('description', ''),
            'severity': data.get('severity', ''),
            'content': data.get('content', ''),
            'timestamp': data.get('timestamp', datetime.now().isoformat()),
            'author_name': data.get('author', {}).get('name', ''),
            'author_email': data.get('author', {}).get('email', ''),
            'author_username': data.get('author', {}).get('username', ''),
        }
        
        try:
            return template.format(**template_vars)
        except KeyError as e:
            logger.warning(f"模板格式化失败，缺少变量: {e}")
            return template
    
    def _send_email(self, to_email: str, subject: str, body: str, 
                   smtp_config: Dict) -> bool:
        """
        发送邮件
        
        Args:
            to_email: 收件人邮箱
            subject: 邮件主题
            body: 邮件内容
            smtp_config: SMTP配置
            
        Returns:
            是否发送成功
        """
        try:
            # 创建邮件消息
            msg = MIMEMultipart()
            msg['From'] = smtp_config.get('smtp_user', '')
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # 添加邮件正文
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # 连接SMTP服务器
            smtp_host = smtp_config.get('smtp_host', '')
            smtp_port = smtp_config.get('smtp_port', 587)
            use_tls = smtp_config.get('use_tls', True)
            
            server = smtplib.SMTP(smtp_host, smtp_port)
            
            if use_tls:
                server.starttls()
            
            # 登录
            smtp_user = smtp_config.get('smtp_user', '')
            smtp_password = smtp_config.get('smtp_password', '')
            server.login(smtp_user, smtp_password)
            
            # 发送邮件
            server.send_message(msg)
            
            # 关闭连接
            server.quit()
            
            return True
            
        except Exception as e:
            logger.error(f"发送邮件失败: {e}")
            return False
    
    def get_author_contact_info(self, result: Dict) -> Dict:
        """
        获取作者联系方式
        
        Args:
            result: 扫描结果
            
        Returns:
            联系方式字典
        """
        author = result.get('author', {})
        
        contact_info = {
            'username': author.get('username', ''),
            'name': author.get('name', ''),
            'email': author.get('email', ''),
            'profile_url': author.get('profile_url', ''),
            'has_email': bool(author.get('email')),
            'has_profile': bool(author.get('profile_url')),
        }
        
        # 尝试从提交历史获取更多信息
        if not contact_info['email']:
            try:
                commits = self.github_client.get_commits(
                    result['repo_name'],
                    path=result['file_path']
                )
                
                for commit in commits:
                    if 'commit' in commit and 'author' in commit['commit']:
                        commit_author = commit['commit']['author']
                        if commit_author.get('email'):
                            contact_info['email'] = commit_author['email']
                            contact_info['has_email'] = True
                            break
                            
            except Exception as e:
                logger.debug(f"获取提交历史失败: {e}")
        
        return contact_info
