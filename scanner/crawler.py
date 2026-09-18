"""
crawler.py
----------
Implements project steps 3-4:
  3. Collect website request-response data using HTTP libraries.
  4. Preprocess inputs by identifying parameters and forms.

The crawler performs a small, breadth-first walk of a target site
(bounded by MAX_CRAWL_DEPTH / MAX_PAGES) and returns a list of
"attack surfaces" - individual points where user input reaches the
application (a query-string parameter or an HTML form field).
"""

import time
import logging
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from . import config

logger = logging.getLogger(__name__)


class AttackSurface:
    """A single injectable point discovered on the target site."""

    def __init__(self, url, method, params, source_page):
        self.url = url                # endpoint that receives the input
        self.method = method.upper()  # "GET" or "POST"
        self.params = params          # dict[name] -> default/sample value
        self.source_page = source_page  # page the surface was found on

    def __repr__(self):
        return f"<AttackSurface {self.method} {self.url} params={list(self.params)}>"


class CrawlResult:
    """Everything the crawler gathered about a target."""

    def __init__(self):
        self.pages = {}            # url -> requests.Response
        self.attack_surfaces = []  # list[AttackSurface]


def _same_site(base_netloc, candidate_url):
    parsed = urlparse(candidate_url)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return False
    return parsed.netloc in ("", base_netloc)


def _extract_query_params(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    # Reduce list values to a single representative sample value.
    return {k: (v[0] if v else "test") for k, v in qs.items()}


def _extract_forms(soup, page_url):
    """Turn each <form> on a page into an AttackSurface."""
    surfaces = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = form.get("method", "get")
        target_url = urljoin(page_url, action)

        params = {}
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            field_type = (field.get("type") or "text").lower()
            if field_type in ("submit", "button", "image", "reset", "file"):
                continue
            params[name] = field.get("value") or "test"

        if params:
            surfaces.append(AttackSurface(target_url, method, params, page_url))
    return surfaces


def crawl(start_url, session=None):
    """
    Breadth-first crawl of `start_url`, bounded by config limits.

    Returns a CrawlResult containing fetched pages and discovered
    attack surfaces (query-string params + form fields).
    """
    session = session or requests.Session()
    session.headers.update({"User-Agent": config.USER_AGENT})

    base_netloc = urlparse(start_url).netloc
    result = CrawlResult()

    visited = set()
    queue = deque([(start_url, 0)])

    while queue and len(result.pages) < config.MAX_PAGES:
        url, depth = queue.popleft()
        url = url.split("#")[0]
        if url in visited or depth > config.MAX_CRAWL_DEPTH:
            continue
        visited.add(url)

        try:
            response = session.get(url, timeout=config.REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("Could not fetch %s: %s", url, exc)
            continue

        result.pages[url] = response
        time.sleep(config.REQUEST_DELAY)

        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type and not response.text.strip().startswith("<"):
            continue

        soup = BeautifulSoup(response.text, "html.parser")

        # Query-string params on the page URL itself.
        qs_params = _extract_query_params(url)
        if qs_params:
            result.attack_surfaces.append(
                AttackSurface(url, "GET", qs_params, source_page=url)
            )

        # Forms found on the page.
        result.attack_surfaces.extend(_extract_forms(soup, url))

        # Queue same-site links for the next depth level.
        if depth < config.MAX_CRAWL_DEPTH:
            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"]).split("#")[0]
                if _same_site(base_netloc, next_url) and next_url not in visited:
                    queue.append((next_url, depth + 1))

    return result
