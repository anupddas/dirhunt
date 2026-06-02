# -*- coding: utf-8 -*-
"""Tests for CMS detection (dirhunt/cms.py) and its integration in processors."""
import unittest

import requests
import requests_mock
from bs4 import BeautifulSoup

from dirhunt.cms import detect_cms_from_asset, detect_cms_from_html
from dirhunt.processors import ProcessHtmlRequest
from dirhunt.tests.base import CrawlerTestBase


# ---------------------------------------------------------------------------
# Unit tests for dirhunt/cms.py
# ---------------------------------------------------------------------------

class TestDetectCmsFromAsset(unittest.TestCase):
    """detect_cms_from_asset — path-based fingerprinting."""

    def test_detects_wordpress_via_wp_content(self):
        cms = detect_cms_from_asset('/wp-content/themes/mytheme/style.css', set())
        self.assertIsNotNone(cms)
        self.assertEqual(cms['flag'], 'wordpress')

    def test_detects_wordpress_via_wp_includes(self):
        cms = detect_cms_from_asset('/wp-includes/js/jquery.js', set())
        self.assertIsNotNone(cms)
        self.assertEqual(cms['flag'], 'wordpress')

    def test_detects_drupal_via_sites_default(self):
        cms = detect_cms_from_asset('/sites/default/files/image.png', set())
        self.assertIsNotNone(cms)
        self.assertEqual(cms['flag'], 'drupal')

    def test_detects_joomla_via_media_jui(self):
        cms = detect_cms_from_asset('/media/jui/js/jquery.min.js', set())
        self.assertIsNotNone(cms)
        self.assertEqual(cms['flag'], 'joomla')

    def test_detects_magento_via_pub_static(self):
        cms = detect_cms_from_asset('/pub/static/frontend/Magento/luma/en_US/mage/bootstrap.js', set())
        self.assertIsNotNone(cms)
        self.assertEqual(cms['flag'], 'magento')

    def test_returns_none_for_unknown_path(self):
        cms = detect_cms_from_asset('/assets/img/logo.png', set())
        self.assertIsNone(cms)

    def test_skips_already_flagged_cms(self):
        # WordPress already in flags — should not be returned again
        cms = detect_cms_from_asset('/wp-content/themes/x/style.css', {'wordpress'})
        self.assertIsNone(cms)

    def test_detects_shopify_via_cdn(self):
        cms = detect_cms_from_asset('https://cdn.shopify.com/s/files/1/0001/theme.js', set())
        self.assertIsNotNone(cms)
        self.assertEqual(cms['flag'], 'shopify')


class TestDetectCmsFromHtml(unittest.TestCase):
    """detect_cms_from_html — meta tag, header and pattern based."""

    def _soup(self, html):
        return BeautifulSoup(html, 'html.parser')

    # --- WordPress ---
    def test_detects_wordpress_via_generator_meta(self):
        html = '<html><head><meta name="generator" content="WordPress 6.2"></head></html>'
        matches = detect_cms_from_html(html, self._soup(html), {}, set())
        flags = {m['flag'] for m in matches}
        self.assertIn('wordpress', flags)

    def test_detects_wordpress_via_html_pattern(self):
        html = '<html><body><script src="/wp-login.php"></script></body></html>'
        matches = detect_cms_from_html(html, self._soup(html), {}, set())
        flags = {m['flag'] for m in matches}
        self.assertIn('wordpress', flags)

    # --- Drupal ---
    def test_detects_drupal_via_generator_meta(self):
        html = '<html><head><meta name="generator" content="Drupal 9 (https://www.drupal.org)"></head></html>'
        matches = detect_cms_from_html(html, self._soup(html), {}, set())
        flags = {m['flag'] for m in matches}
        self.assertIn('drupal', flags)

    def test_detects_drupal_via_x_generator_header(self):
        html = '<html></html>'
        headers = {'X-Generator': 'Drupal 9 (https://www.drupal.org)'}
        matches = detect_cms_from_html(html, self._soup(html), headers, set())
        flags = {m['flag'] for m in matches}
        self.assertIn('drupal', flags)

    def test_detects_drupal_via_drupal_cache_header(self):
        html = '<html></html>'
        headers = {'X-Drupal-Cache': 'HIT'}
        matches = detect_cms_from_html(html, self._soup(html), headers, set())
        flags = {m['flag'] for m in matches}
        self.assertIn('drupal', flags)

    # --- Joomla ---
    def test_detects_joomla_via_generator_meta(self):
        html = '<html><head><meta name="generator" content="Joomla! - Open Source Content Management"></head></html>'
        matches = detect_cms_from_html(html, self._soup(html), {}, set())
        flags = {m['flag'] for m in matches}
        self.assertIn('joomla', flags)

    # --- Shopify ---
    def test_detects_shopify_via_html_pattern(self):
        html = '<html><body><script>Shopify.theme = {}</script></body></html>'
        matches = detect_cms_from_html(html, self._soup(html), {}, set())
        flags = {m['flag'] for m in matches}
        self.assertIn('shopify', flags)

    # --- No false positive ---
    def test_returns_empty_for_plain_html(self):
        html = '<html><head><title>Hello</title></head><body><p>World</p></body></html>'
        matches = detect_cms_from_html(html, self._soup(html), {}, set())
        self.assertEqual(matches, [])

    def test_skips_already_flagged(self):
        html = '<html><head><meta name="generator" content="WordPress 6.2"></head></html>'
        matches = detect_cms_from_html(html, self._soup(html), {}, {'wordpress'})
        flags = {m['flag'] for m in matches}
        self.assertNotIn('wordpress', flags)

    def test_detects_multiple_cms_in_one_page(self):
        """Edge case: a page that bizarrely triggers two CMS fingerprints."""
        html = ('<html><head>'
                '<meta name="generator" content="WordPress 6.2">'
                '<meta name="generator" content="Joomla! CMS">'
                '</head></html>')
        matches = detect_cms_from_html(html, self._soup(html), {}, set())
        flags = {m['flag'] for m in matches}
        # WordPress detected first via meta; Joomla may also be present
        self.assertIn('wordpress', flags)


# ---------------------------------------------------------------------------
# Integration tests for ProcessHtmlRequest
# ---------------------------------------------------------------------------

class TestProcessHtmlRequestCmsDetection(CrawlerTestBase, unittest.TestCase):
    """Ensure CMS flags and names reach the processor layer."""

    def _make_response(self, html, url='http://domain.com/path/'):
        with requests_mock.mock() as m:
            m.register_uri('GET', url, text=html,
                           headers={'Content-Type': 'text/html'}, status_code=200)
            return requests.get(url)

    def _make_processor(self, html):
        resp = self._make_response(html)
        crawler_url = self.get_crawler_url()
        crawler_url.resp = resp  # attach so headers are available
        return ProcessHtmlRequest(resp, crawler_url)

    def test_wordpress_flag_set_via_asset_path(self):
        html = ('<html><head>'
                '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
                '</head><body></body></html>')
        proc = self._make_processor(html)
        soup = BeautifulSoup(html, 'html.parser')
        proc.process(html, soup)
        self.assertIn('wordpress', proc.crawler_url.flags)
        self.assertIn('WordPress', proc.cms_detected)

    def test_drupal_flag_set_via_meta_generator(self):
        html = ('<html><head>'
                '<meta name="generator" content="Drupal 9 (https://www.drupal.org)">'
                '</head><body></body></html>')
        proc = self._make_processor(html)
        soup = BeautifulSoup(html, 'html.parser')
        proc.process(html, soup)
        self.assertIn('drupal', proc.crawler_url.flags)
        self.assertIn('Drupal', proc.cms_detected)

    def test_joomla_flag_set_via_asset(self):
        html = ('<html><head>'
                '<script src="/media/jui/js/jquery.min.js"></script>'
                '</head><body></body></html>')
        proc = self._make_processor(html)
        soup = BeautifulSoup(html, 'html.parser')
        proc.process(html, soup)
        self.assertIn('joomla', proc.crawler_url.flags)
        self.assertIn('Joomla', proc.cms_detected)

    def test_cms_name_printed_in_str(self):
        html = ('<html><head>'
                '<link href="/wp-content/themes/x/style.css" rel="stylesheet">'
                '</head><body></body></html>')
        proc = self._make_processor(html)
        soup = BeautifulSoup(html, 'html.parser')
        proc.process(html, soup)
        self.assertIn('WordPress', str(proc))

    def test_cms_name_in_json(self):
        html = ('<html><head>'
                '<link href="/wp-content/themes/x/style.css" rel="stylesheet">'
                '</head><body></body></html>')
        proc = self._make_processor(html)
        soup = BeautifulSoup(html, 'html.parser')
        proc.process(html, soup)
        self.assertIn('WordPress', proc.json()['cms_detected'])

    def test_no_cms_detected_on_plain_page(self):
        html = '<html><head><title>Hello</title></head><body><p>World</p></body></html>'
        proc = self._make_processor(html)
        soup = BeautifulSoup(html, 'html.parser')
        proc.process(html, soup)
        self.assertEqual(proc.cms_detected, set())
        self.assertNotIn('CMS detected', str(proc))


if __name__ == '__main__':
    unittest.main()
