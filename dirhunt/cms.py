# -*- coding: utf-8 -*-
"""
CMS detection for dirhunt.

Each CMS entry contains one or more of these signature types:
  - asset_paths   : substrings looked for inside asset/link src/href paths
  - meta_names    : <meta name="..."> values (lowercased)
  - meta_content  : <meta ...content="..."> value substrings (lowercased)
  - html_comments : substrings searched in HTML comment nodes
  - headers       : HTTP response header name→value substring pairs
  - html_patterns : arbitrary substrings anywhere in the raw HTML text
"""

CMS_SIGNATURES = [
    {
        'name': 'WordPress',
        'flag': 'wordpress',
        'asset_paths': ['wp-content/', 'wp-includes/'],
        'meta_names': ['generator'],
        'meta_content': ['wordpress'],
        'html_patterns': ['/wp-login.php', 'wp-embed.min.js'],
    },
    {
        'name': 'Drupal',
        'flag': 'drupal',
        'asset_paths': ['/sites/default/files/', '/misc/drupal.js', '/core/misc/drupal.js'],
        'meta_names': ['generator'],
        'meta_content': ['drupal'],
        'headers': {'X-Generator': 'drupal', 'X-Drupal-Cache': ''},
        'html_patterns': ['Drupal.settings', 'drupal.org'],
    },
    {
        'name': 'Joomla',
        'flag': 'joomla',
        'asset_paths': ['/media/jui/', '/media/system/js/', '/components/com_'],
        'meta_names': ['generator'],
        'meta_content': ['joomla'],
        'html_patterns': ['/administrator/index.php'],
    },
    {
        'name': 'Magento',
        'flag': 'magento',
        'asset_paths': ['/skin/frontend/', '/js/mage/', '/pub/static/frontend/'],
        'meta_names': ['generator'],
        'meta_content': ['magento'],
        'html_patterns': ['Mage.Cookies', 'mage/cookies'],
    },
    {
        'name': 'PrestaShop',
        'flag': 'prestashop',
        'asset_paths': ['/themes/default-bootstrap/', '/modules/ps_'],
        'html_patterns': ['prestashop', 'PrestaShop'],
        'headers': {'X-Powered-By': 'prestashop'},
    },
    {
        'name': 'TYPO3',
        'flag': 'typo3',
        'asset_paths': ['/typo3/', '/typo3conf/'],
        'meta_content': ['typo3'],
        'html_patterns': ['typo3temp', 'typo3conf'],
    },
    {
        'name': 'Shopify',
        'flag': 'shopify',
        'asset_paths': ['cdn.shopify.com'],
        'html_patterns': ['Shopify.theme', 'shopify_pay'],
        'meta_content': ['shopify'],
    },
    {
        'name': 'Wix',
        'flag': 'wix',
        'asset_paths': ['static.wixstatic.com', 'wix-warmup-data'],
        'html_patterns': ['wixsite.com', 'X-Wix-Published-Version'],
    },
    {
        'name': 'Squarespace',
        'flag': 'squarespace',
        'asset_paths': ['static.squarespace.com', 'squarespace-cdn.com'],
        'html_patterns': ['Static.SQUARESPACE_CONTEXT', 'squarespace.com'],
    },
    {
        'name': 'Ghost',
        'flag': 'ghost',
        'asset_paths': ['/ghost/'],
        'meta_content': ['ghost'],
        'html_patterns': ['ghost.io', 'content="Ghost '],
    },
]


def detect_cms_from_asset(asset_path, current_flags):
    """
    Check a single asset URL path against all CMS asset_path signatures.

    :param asset_path: str — the URL path of a discovered asset
    :param current_flags: set — existing flags on the CrawlerUrl
    :return: dict|None — the matching CMS entry, or None
    """
    for cms in CMS_SIGNATURES:
        if cms['flag'] in current_flags:
            continue
        for pattern in cms.get('asset_paths', []):
            if pattern in asset_path:
                return cms
    return None


def detect_cms_from_html(text, soup, response_headers, current_flags):
    """
    Check raw HTML text, BeautifulSoup meta tags, and response headers
    against all CMS signatures.

    :param text: str — raw response body
    :param soup: BeautifulSoup — parsed document
    :param response_headers: dict-like — HTTP response headers
    :param current_flags: set — existing flags on the CrawlerUrl
    :return: list[dict] — all newly matched CMS entries
    """
    matched = []
    for cms in CMS_SIGNATURES:
        if cms['flag'] in current_flags:
            continue

        # 1. Raw HTML patterns
        for pattern in cms.get('html_patterns', []):
            if pattern in text:
                matched.append(cms)
                break  # no need to check further for this CMS
        else:
            # 2. <meta name="generator" content="..."> and similar
            if soup:
                for meta in soup.find_all('meta'):
                    name = (meta.attrs.get('name') or '').lower()
                    content = (meta.attrs.get('content') or '').lower()
                    if name in cms.get('meta_names', []) and \
                            any(p in content for p in cms.get('meta_content', [])):
                        matched.append(cms)
                        break

            # 3. HTTP response headers
            for header_name, header_value in cms.get('headers', {}).items():
                actual = (response_headers.get(header_name) or '').lower()
                if header_value == '' and actual:
                    # presence-only check
                    matched.append(cms)
                    break
                if header_value and header_value in actual:
                    matched.append(cms)
                    break

    return matched
