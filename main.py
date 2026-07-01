#!/usr/bin/env python3
"""
Key Leak Detector - API密钥泄露检测工具

主程序入口，提供命令行接口。
"""

import os
import sys
from pathlib import Path
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.scanner import Scanner
from src.notifier import Notifier
from src.utils import load_config, setup_logging

console = Console()

@click.group()
@click.option('--config', '-c', default='config.yaml', help='配置文件路径')
@click.pass_context
def cli(ctx, config):
    """Key Leak Detector - API密钥泄露检测工具"""
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config
    
    # 加载配置
    try:
        ctx.obj['config'] = load_config(config)
    except Exception as e:
        console.print(f"[red]错误: 加载配置文件失败: {e}[/red]")
        sys.exit(1)
    
    # 设置日志
    setup_logging(ctx.obj['config'].get('logging', {}))

@cli.command()
@click.option('--query', '-q', help='自定义搜索查询')
@click.option('--max-results', '-m', default=100, help='最大结果数')
@click.pass_context
def scan(ctx, query, max_results):
    """扫描GitHub仓库中的API密钥泄露"""
    config = ctx.obj['config']
    
    console.print(Panel(
        "[bold green]开始扫描API密钥泄露...[/bold green]",
        title="Key Leak Detector",
        border_style="green"
    ))
    
    try:
        scanner = Scanner(config)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("正在扫描...", total=None)
            
            # 执行扫描
            results = scanner.scan(query=query, max_results=max_results)
            
            progress.update(task, description=f"扫描完成，发现 {len(results)} 个潜在泄露")
        
        # 显示结果
        if results:
            display_results(results)
        else:
            console.print("[yellow]未发现API密钥泄露[/yellow]")
        
        # 保存报告（无论是否找到结果都保存）
        save_report(config, results)
        
    except Exception as e:
        console.print(f"[red]扫描过程中发生错误: {e}[/red]")
        sys.exit(1)

@cli.command()
@click.argument('report_file')
@click.pass_context
def notify(ctx, report_file):
    """根据报告文件发送通知"""
    config = ctx.obj['config']
    
    console.print(Panel(
        f"[bold blue]处理报告文件: {report_file}[/bold blue]",
        title="Key Leak Detector",
        border_style="blue"
    ))
    
    try:
        # 加载报告
        import json
        with open(report_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        # 发送通知
        notifier = Notifier(config)
        notified_count = notifier.notify_all(results)
        
        console.print(f"[green]成功发送 {notified_count} 个通知[/green]")
        
    except Exception as e:
        console.print(f"[red]发送通知时发生错误: {e}[/red]")
        sys.exit(1)

@cli.command()
@click.pass_context
def config_check(ctx):
    """检查配置文件"""
    config = ctx.obj['config']
    
    console.print(Panel(
        "[bold yellow]配置检查[/bold yellow]",
        title="Key Leak Detector",
        border_style="yellow"
    ))
    
    # 检查GitHub Token
    github_token = config.get('github', {}).get('token', '')
    if github_token and not github_token.startswith('${'):
        console.print("[green]✓ GitHub Token 已配置[/green]")
    else:
        console.print("[red]✗ GitHub Token 未配置或使用默认值[/red]")
    
    # 检查通知配置
    notification_config = config.get('notification', {})
    enabled_methods = notification_config.get('enabled_methods', [])
    
    if 'email' in enabled_methods:
        smtp_host = notification_config.get('email', {}).get('smtp_host', '')
        if smtp_host and not smtp_host.startswith('${'):
            console.print("[green]✓ 邮件通知已配置[/green]")
        else:
            console.print("[red]✗ 邮件通知未正确配置[/red]")
    
    if 'github_issue' in enabled_methods:
        console.print("[green]✓ GitHub Issue 通知已启用[/green]")
    
    # 检查检测类型
    detection_config = config.get('detection', {})
    enabled_types = detection_config.get('enabled_types', [])
    console.print(f"[blue]✓ 已启用 {len(enabled_types)} 种密钥检测类型[/blue]")

def display_results(results):
    """显示扫描结果"""
    table = Table(title="扫描结果")
    
    table.add_column("仓库", style="cyan")
    table.add_column("文件", style="magenta")
    table.add_column("行号", style="green")
    table.add_column("密钥类型", style="yellow")
    table.add_column("严重程度", style="red")
    
    for result in results:
        table.add_row(
            result.get('repo_name', ''),
            result.get('file_path', ''),
            str(result.get('line_number', '')),
            result.get('key_type', ''),
            result.get('severity', '')
        )
    
    console.print(table)

def save_report(config, results):
    """保存扫描报告"""
    import json
    from datetime import datetime
    
    report_config = config.get('report', {})
    output_dir = report_config.get('output_dir', 'reports')
    
    # 创建输出目录
    Path(output_dir).mkdir(exist_ok=True)
    
    # 生成报告文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = Path(output_dir) / f"scan_report_{timestamp}.json"
    
    # 保存报告
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    console.print(f"[green]报告已保存到: {report_file}[/green]")
    console.print(f"[blue]扫描结果: 发现 {len(results)} 个潜在泄露[/blue]")

if __name__ == '__main__':
    cli()