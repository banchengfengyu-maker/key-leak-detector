"""
Web discovery client.

Uses web search engines or SearXNG to discover GitHub candidate URLs
without consuming GitHub code search API quota.
"""

import hashlib
import html
from datetime import datetime
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse, unquote

import requests

logger = logging.getLogger(__name__)


GITHUB_BLOB_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)"
    r"/blob/(?P<branch>[^/]+)/(?P<path>[^\"'?#>]+)"
)

GITHUB_RELATIVE_BLOB_RE = re.compile(
    r"^/(?P<owner>[^/]+)/(?P<repo>[^/]+)/(?P<kind>blob|raw)/(?P<branch>[^/]+)/(?P<path>[^\"'?#>]+)"
)


class WebDiscoveryClient:
    """Discover GitHub candidate files via web search."""

    def __init__(self, config: Dict[str, Any]):
        discovery = config.get('discovery', {})
        self.provider = discovery.get('web_provider', 'duckduckgo')
        self.base_url = discovery.get('web_base_url', '').strip()
        self.web_query_prefix = discovery.get('web_query_prefix', 'site:github.com')
        self.github_query_prefix = discovery.get('github_query_prefix', '')
        self.web_query_templates = discovery.get('web_query_templates', [
            'site:github.com ".env" {query}',
        ])
        self.bing_query_prefix = discovery.get('bing_query_prefix', 'site:github.com')
        self.timeout = float(discovery.get('timeout_seconds', 12))
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({
            'User-Agent': 'Key-Leak-Detector/1.0'
        })

    def search(self, query: str, max_results: int = 20) -> List[Dict[str, Any]]:
        """Search the web and return parsed GitHub candidate URLs."""
        queries = []
        for template in self.web_query_templates:
            queries.append(('bing', self._build_query(query, engine='bing', template=template)))
            queries.append(('github_web', self._build_query(query, engine='github_web', template=template)))
            queries.append(('searxng', self._build_query(query, engine='web', template=template)))
            queries.append(('duckduckgo', self._build_query(query, engine='web', template=template)))

        order = [self.provider, 'bing', 'github_web', 'searxng', 'duckduckgo']
        tried = set()
        for engine_name in order:
            if engine_name in tried:
                continue
            tried.add(engine_name)

            engine_query = None
            for eng, q in queries:
                if eng == engine_name:
                    engine_query = q
                    break
            if not engine_query:
                continue

            if engine_name == 'github_web':
                results = self._search_github_web(engine_query, max_results)
            elif engine_name == 'bing':
                results = self._search_bing(engine_query, max_results)
            elif engine_name == 'searxng' and self.base_url:
                results = self._search_searxng(engine_query, max_results)
            elif engine_name == 'duckduckgo':
                results = self._search_duckduckgo(engine_query, max_results)
            else:
                continue

            if results:
                return results

        return []

    def _build_query(self, query: str, engine: str, template: str = None) -> str:
        query = query.strip()
        if template:
            query = template.format(query=query)

        if engine == 'bing':
            prefix = self.bing_query_prefix.strip()
            return f"{prefix} {query}".strip() if prefix else query.strip()

        if engine == 'github_web':
            prefix = self.github_query_prefix.strip()
            return f"{prefix} {query}".strip() if prefix else query.strip()

        prefix = self.web_query_prefix.strip()
        return f"{prefix} {query}".strip() if prefix else query.strip()

    def _search_searxng(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        url = self.base_url.rstrip('/') + '/search'
        params = {
            'q': query,
            'format': 'json',
            'language': 'all',
            'safesearch': 0,
        }

        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.debug("SearXNG search failed: %s", exc)
            return []

        return self._extract_candidates_from_results(data.get('results', [])[:max_results], source='searxng')

    def _search_duckduckgo(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        url = 'https://html.duckduckgo.com/html/'
        params = {'q': query}

        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            html_text = response.text
        except Exception as exc:
            logger.debug("DuckDuckGo search failed: %s", exc)
            return []

        return self._extract_candidates_from_html(html_text, source='duckduckgo', max_results=max_results)

    def _search_bing(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        url = 'https://www.bing.com/search'
        params = {'q': query}

        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            html_text = response.text
        except Exception as exc:
            logger.debug("Bing search failed: %s", exc)
            return []

        return self._extract_candidates_from_bing_html(html_text, max_results=max_results)

    def _search_github_web(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        url = 'https://github.com/search'
        params = {'q': query, 'type': 'code'}

        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            html_text = response.text
        except Exception as exc:
            logger.debug("GitHub web search failed: %s", exc)
            return []

        return self._extract_candidates_from_html(html_text, source='github_web', max_results=max_results)

    def _extract_candidates_from_results(self, results: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        seen = set()

        for result in results:
            url = result.get('url', '')
            candidate = self._parse_github_url(url)
            if not candidate:
                continue

            fingerprint = candidate['candidate_fingerprint']
            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            candidate.update({
                'source_engine': source,
                'search_url': url,
                'search_title': result.get('title', ''),
            })
            candidates.append(candidate)

        return candidates

    def _extract_candidates_from_html(self, html_text: str, source: str, max_results: int) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        seen = set()

        for url in self._iter_result_urls(html_text):
            candidate = self._parse_github_url(url)
            if not candidate:
                continue

            fingerprint = candidate['candidate_fingerprint']
            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            candidate.update({
                'source_engine': source,
                'search_url': url,
                'search_title': '',
            })
            candidates.append(candidate)

            if len(candidates) >= max_results:
                break

        return candidates

    def _extract_candidates_from_bing_html(self, html_text: str, max_results: int) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        seen = set()

        for block in re.findall(r'<li class="b_algo".*?</li>', html_text, re.S):
            href_match = re.search(r'<h2>\s*<a[^>]+href="([^"]+)"', block, re.S)
            if not href_match:
                continue

            href = html.unescape(href_match.group(1)).replace('&amp;', '&')
            if href.startswith('//'):
                href = 'https:' + href

            candidate = self._parse_github_url(href)
            if not candidate:
                continue

            fingerprint = candidate['candidate_fingerprint']
            if fingerprint in seen:
                continue

            seen.add(fingerprint)
            candidate.update({
                'source_engine': 'bing',
                'search_url': href,
                'search_title': '',
            })
            candidates.append(candidate)

            if len(candidates) >= max_results:
                break

        return candidates

    def _iter_result_urls(self, html_text: str):
        """Yield likely result URLs from search engine HTML."""
        for raw_href in re.findall(r'href="([^"]+)"', html_text):
            href = html.unescape(raw_href)
            href = href.replace('&amp;', '&')

            if href.startswith('/l/?'):
                parsed = urlparse(href)
                query = parse_qs(parsed.query)
                target = query.get('uddg', [''])[0]
                if target:
                    href = unquote(target)
            elif href.startswith('//'):
                href = 'https:' + href
            elif GITHUB_RELATIVE_BLOB_RE.match(href):
                href = 'https://github.com' + href
            elif href.startswith('/') and ('/blob/' in href or '/raw/' in href):
                href = 'https://github.com' + href

            if 'github.com/' in href or 'raw.githubusercontent.com/' in href:
                yield href

    def _parse_github_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Parse a GitHub blob/raw URL into a candidate record."""
        blob_match = GITHUB_BLOB_RE.search(url)
        if blob_match:
            owner = blob_match.group('owner')
            repo = blob_match.group('repo')
            branch = blob_match.group('branch')
            file_path = blob_match.group('path')
            repo_name = f"{owner}/{repo}"
            payload = f"{repo_name}\0{file_path}\0{branch}".encode('utf-8', errors='replace')

            return {
                'candidate_only': True,
                'repo_name': repo_name,
                'repo_url': f"https://github.com/{repo_name}",
                'owner_username': owner,
                'owner_profile_url': f"https://github.com/{owner}",
                'file_path': file_path,
                'file_url': url,
                'source_query': '',
                'text_match_count': 0,
                'candidate_fingerprint': hashlib.sha256(payload).hexdigest(),
                'approved_for_notification': False,
                'timestamp': datetime.now().isoformat(),
                'source_kind': 'github_blob',
            }

        raw_match = re.search(
            r"https?://raw\.githubusercontent\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/(?P<branch>[^/]+)/(?P<path>.+)",
            url
        )
        if raw_match:
            owner = raw_match.group('owner')
            repo = raw_match.group('repo')
            branch = raw_match.group('branch')
            file_path = raw_match.group('path')
            repo_name = f"{owner}/{repo}"
            payload = f"{repo_name}\0{file_path}\0{branch}".encode('utf-8', errors='replace')

            return {
                'candidate_only': True,
                'repo_name': repo_name,
                'repo_url': f"https://github.com/{repo_name}",
                'owner_username': owner,
                'owner_profile_url': f"https://github.com/{owner}",
                'file_path': file_path,
                'file_url': url,
                'source_query': '',
                'text_match_count': 0,
                'candidate_fingerprint': hashlib.sha256(payload).hexdigest(),
                'approved_for_notification': False,
                'timestamp': datetime.now().isoformat(),
                'source_kind': 'raw_url',
            }

        return None
