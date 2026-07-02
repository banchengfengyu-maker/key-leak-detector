import tempfile
import unittest
from pathlib import Path

from src.notifier import Notifier
from src.key_patterns import PatternMatcher
from src.scanner import DEFAULT_SEARCH_QUERIES, ScanState, Scanner
from src.web_discovery import WebDiscoveryClient


class ScannerSafetyTests(unittest.TestCase):
    def test_mask_secret_does_not_return_full_value(self):
        scanner = Scanner.__new__(Scanner)
        secret = "github_token = ghp_1234567890abcdefghijklmnopqrstuvwxyz"

        masked = scanner._mask_secret(secret)

        self.assertNotEqual(masked, secret)
        self.assertNotIn("1234567890abcdefghijklmnop", masked)

    def test_fingerprint_is_stable_and_does_not_contain_secret(self):
        scanner = Scanner.__new__(Scanner)
        secret = "AKIAIOSFODNN7EXAMPLE"

        first = scanner._fingerprint("owner/repo", ".env", "aws_access_key", secret)
        second = scanner._fingerprint("owner/repo", ".env", "aws_access_key", secret)

        self.assertEqual(first, second)
        self.assertNotIn(secret, first)

    def test_scan_state_marks_recent_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "scan_state.json"
            state = ScanState(str(state_path), cooldown_days=30)

            self.assertFalse(state.is_recent_finding("abc"))
            state.mark_finding("abc")

            self.assertTrue(state.is_recent_finding("abc"))

    def test_notifier_requires_manual_review_by_default(self):
        config = {
            "github": {"token": "ghp_fake_token_for_tests_only"},
            "notification": {
                "enabled_methods": ["github_issue", "email", "report_only"],
                "require_manual_review": True,
            },
        }
        notifier = Notifier(config)
        results = [{
            "repo_name": "owner/repo",
            "file_path": ".env",
            "approved_for_notification": False,
        }]

        self.assertEqual(notifier.notify_all(results), 1)

    def test_basic_author_info_uses_search_result_only(self):
        scanner = Scanner.__new__(Scanner)
        item = {
            "repository": {
                "owner": {
                    "login": "octocat",
                    "html_url": "https://github.com/octocat",
                    "avatar_url": "https://avatars.githubusercontent.com/u/1",
                }
            }
        }

        author = scanner._basic_author_info(item)

        self.assertEqual(author["username"], "octocat")
        self.assertEqual(author["profile_url"], "https://github.com/octocat")
        self.assertEqual(author["email"], "")

    def test_bare_github_token_matches(self):
        matcher = PatternMatcher(["github_token"])
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"

        matches = matcher.find_keys(f"token: {token}")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["key_type"], "github_token")

    def test_bare_stripe_key_matches(self):
        matcher = PatternMatcher(["stripe_key"])
        token = "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz123456"

        matches = matcher.find_keys(f"stripe={token}")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["key_type"], "stripe_key")

    def test_candidate_record_does_not_store_text_match_fragment(self):
        scanner = Scanner.__new__(Scanner)
        item = {
            "path": ".env",
            "html_url": "https://github.com/octocat/demo/blob/main/.env",
            "text_matches": [{
                "fragment": "STRIPE_SECRET=" + "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz123456"
            }],
            "repository": {
                "full_name": "octocat/demo",
                "html_url": "https://github.com/octocat/demo",
                "owner": {
                    "login": "octocat",
                    "html_url": "https://github.com/octocat",
                },
            },
        }

        candidate = scanner._build_candidate(item, '"sk_live_"')

        self.assertTrue(candidate["candidate_only"])
        self.assertEqual(candidate["repo_name"], "octocat/demo")
        self.assertNotIn("fragment", candidate)
        self.assertNotIn("STRIPE_SECRET", str(candidate))
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", str(candidate))

    def test_excluded_candidate_uses_file_filters(self):
        scanner = Scanner.__new__(Scanner)
        scanner.false_positive_filter = type("Filter", (), {
            "_is_excluded_file": staticmethod(lambda path: path.endswith(".md")),
            "_is_excluded_dir": staticmethod(lambda path: False),
        })()
        item = {"path": "README.md"}

        self.assertTrue(scanner._is_excluded_candidate(item))

    def test_web_discovery_parse_github_blob_url(self):
        client = WebDiscoveryClient({
            "discovery": {
                "web_provider": "duckduckgo",
                "web_base_url": "",
                "web_query_prefix": "site:github.com",
                "github_query_prefix": "site:github.com",
            }
        })

        candidate = client._parse_github_url(
            "https://github.com/octocat/demo/blob/main/app.py"
        )

        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["repo_name"], "octocat/demo")
        self.assertEqual(candidate["file_path"], "app.py")
        self.assertEqual(candidate["source_kind"], "github_blob")

    def test_web_discovery_parse_relative_github_blob_url(self):
        client = WebDiscoveryClient({
            "discovery": {
                "web_provider": "duckduckgo",
                "web_base_url": "",
                "web_query_prefix": "site:github.com",
                "github_query_prefix": "site:github.com",
            }
        })

        candidate = client._parse_github_url(
            "https://github.com/octocat/demo/blob/main/app.py"
        )

        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["repo_url"], "https://github.com/octocat/demo")

    def test_bing_candidate_parser(self):
        client = WebDiscoveryClient({
            "discovery": {
                "web_provider": "bing",
                "web_base_url": "",
                "web_query_prefix": "site:github.com",
                "github_query_prefix": "site:github.com",
                "bing_query_prefix": "site:github.com",
            }
        })
        html = '''
        <html><body>
        <li class="b_algo"><h2><a href="https://github.com/octocat/demo/blob/main/app.py">demo</a></h2></li>
        </body></html>
        '''
        candidates = client._extract_candidates_from_bing_html(html, max_results=5)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["repo_name"], "octocat/demo")

    def test_web_discovery_timeout_config(self):
        client = WebDiscoveryClient({
            "discovery": {
                "web_provider": "bing",
                "timeout_seconds": 6,
            }
        })
        self.assertEqual(client.timeout, 6.0)

    def test_default_web_queries_use_repo_file_clues(self):
        self.assertTrue(any(".env" in q or "config" in q for q in DEFAULT_SEARCH_QUERIES))


if __name__ == "__main__":
    unittest.main()
