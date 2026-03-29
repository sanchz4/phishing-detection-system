# src/domain_discovery.py
"""
Enhanced Domain Discovery Module for Phishing Detection System
Integrates deep_string_hunter capabilities with existing phishing detection
"""

import requests
import os
import time
import csv
import json
import idna
import unicodedata
from urllib.parse import urlparse
from datetime import datetime
from dateutil import parser as dateparse
import pandas as pd

# Optional fast fuzzy lib
try:
    from rapidfuzz.distance import Levenshtein
    HAS_RAPIDFUZZ = True
except Exception:
    HAS_RAPIDFUZZ = False

class DomainDiscovery:
    def __init__(self, config_path="config.json"):
        self.load_config(config_path)
        self.setup_api_clients()
        self.discovered_domains = {}
        
    def load_config(self, config_path):
        """Load configuration and API keys"""
        try:
            with open(config_path, 'r') as f:
                self.config = json.load(f)
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            self.config = {}
    
    def setup_api_clients(self):
        """Setup API clients from config"""
        # Get API keys from config with environment fallback
        icann_config = self.config.get("icann", {})
        self.vt_api_key = icann_config.get("virustotal_key") or os.getenv("VT_API_KEY")
        self.securitytrails_key = icann_config.get("securitytrails_key") or os.getenv("ST_KEY")
        self.urlscan_key = icann_config.get("urlscan_key") or os.getenv("URLSCAN_KEY")
        
        self.headers_vt = {"x-apikey": self.vt_api_key} if self.vt_api_key else {}
        self.base_vt = "https://www.virustotal.com/api/v3"
        
        # Tune parameters
        self.vt_page_limit = 20  # Reduced for stability
        self.urlscan_limit = 30  # Reduced for stability
        self.crtsh_timeout = 15  # Reduced timeout
        self.rate_sleep = 1.0    # Increased rate limiting
        
        print("✅ Domain Discovery initialized with API clients")

    # -----------------------------
    # Variant generators (from deep_string_hunter)
    # -----------------------------
    def normalize_unicode(self, s: str) -> str:
        return unicodedata.normalize("NFKC", s)

    def to_punycode(self, domain: str) -> str:
        try:
            return idna.encode(domain).decode()
        except Exception:
            return domain

    def from_punycode(self, domain: str) -> str:
        try:
            return idna.decode(domain)
        except Exception:
            return domain

    def gen_typos(self, domain: str, max_edits=1):
        """Generate simple typo variants for a single label string"""
        domain = domain.lower()
        typos = set()
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
        L = len(domain)
        
        # Only generate a limited number of typos
        if L > 15:  # Skip fuzzy for long domains
            return typos
            
        # deletion
        for i in range(min(L, 10)):  # Limit deletions
            typos.add(domain[:i] + domain[i+1:])
        # insertion/substitution
        for i in range(min(L+1, 10)):  # Limit positions
            for c in alphabet[:20]:  # Limit alphabet
                typos.add(domain[:i] + c + domain[i:])
                if i < L:
                    typos.add(domain[:i] + c + domain[i+1:])
        # transposition
        for i in range(min(L-1, 5)):  # Limit transpositions
            s = list(domain)
            s[i], s[i+1] = s[i+1], s[i]
            typos.add("".join(s))
            
        return {t for t in typos if 2 <= len(t) <= 20}  # Strict length limits

    # Homoglyph mapping
    HOMOGLYPHS = {
        'a': ['@', '4'],
        'i': ['1', 'l'],
        'o': ['0'],
        's': ['5', '$'],
        'e': ['3'],
        't': ['7'],
    }

    def gen_homoglyphs(self, domain: str, max_variants=20):
        """Generate limited homoglyph variants"""
        domain = domain.lower()
        variants = set([domain])
        
        if len(domain) > 15:  # Skip for long domains
            return variants
            
        for i,ch in enumerate(domain[:10]):  # Only first 10 chars
            if ch in self.HOMOGLYPHS:
                for rep in self.HOMOGLYPHS[ch][:2]:  # Only 2 replacements per char
                    v = domain[:i] + rep + domain[i+1:]
                    variants.add(v)
        
        return set(list(variants)[:max_variants])

    # -----------------------------
    # Source queries with improved error handling
    # -----------------------------
    def query_crtsh_for_token(self, token: str, timeout=15, max_retries=2):
        """Query crt.sh for SANs containing the token with retry logic"""
        out = set()
        token = token.strip()
        
        def make_request(url, retry_count=0):
            try:
                r = requests.get(url, timeout=timeout)
                if r.status_code == 200:
                    try:
                        return r.json()
                    except ValueError:
                        return None
                elif r.status_code == 429 and retry_count < max_retries:
                    time.sleep(5)
                    return make_request(url, retry_count + 1)
            except requests.exceptions.Timeout:
                if retry_count < max_retries:
                    print(f"    ⚠️ crt.sh timeout, retrying...")
                    time.sleep(2)
                    return make_request(url, retry_count + 1)
                else:
                    print(f"    ❌ crt.sh timeout after {max_retries} retries")
            except Exception as ex:
                if retry_count < max_retries:
                    time.sleep(2)
                    return make_request(url, retry_count + 1)
            return None

        # Generic search
        url = f"https://crt.sh/?q={requests.utils.quote(token)}&output=json"
        items = make_request(url)
        
        if items:
            for e in items[:50]:  # Limit results
                name = e.get("name_value") or e.get("common_name")
                if not name:
                    continue
                for n in str(name).splitlines()[:3]:  # Limit lines
                    n = n.strip().lower()
                    if token in n and len(n) < 100:  # Reasonable length
                        out.add(n)

        # Wildcard search if token looks like domain
        if '.' in token and len(token) < 30:
            q = f"%25.{token}"
            url2 = f"https://crt.sh/?q={requests.utils.quote(q)}&output=json"
            items2 = make_request(url2)
            
            if items2:
                for e in items2[:50]:  # Limit results
                    name = e.get("name_value") or e.get("common_name")
                    if not name:
                        continue
                    for n in str(name).splitlines()[:3]:
                        n = n.strip().lower()
                        if token in n and len(n) < 100:
                            out.add(n)
        
        time.sleep(self.rate_sleep)
        return out

    def query_alternate_ct_sources(self, token: str):
        """Query alternative Certificate Transparency sources"""
        out = set()
        token = token.strip()
        
        # Cert Spotter API
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={token}&include_subdomains=true&expand=dns_names"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for cert in data[:20]:  # Limit
                    for name in cert.get('dns_names', [])[:5]:  # Limit per cert
                        if token in name.lower() and len(name) < 100:
                            out.add(name.lower())
        except Exception as e:
            pass  # Silent fail for fallback
            
        return out

    def vt_search(self, query: str, limit=20):
        """VirusTotal /search with better error handling"""
        if not self.vt_api_key:
            return []
        
        url = f"{self.base_vt}/search"
        params = {"query": query, "limit": limit}
        results = []
        
        try:
            r = requests.get(url, headers=self.headers_vt, params=params, timeout=20)
            if r.status_code == 401:
                print("VirusTotal API invalid or unauthorized.")
                return []
            if r.status_code == 429:
                print("VT rate limit reached; skipping VT search")
                return []
            r.raise_for_status()
            
            j = r.json()
            for item in j.get("data", [])[:limit]:  # Hard limit
                idv = item.get("id")
                if idv:
                    results.append(idv)
                    
        except Exception as e:
            print(f"    ⚠️ VT search error: {e}")
            
        time.sleep(1)  # VT rate limiting
        return list(set(results))

    def vt_domain_report(self, domain: str):
        if not self.vt_api_key:
            return None
        try:
            url = f"{self.base_vt}/domains/{domain}"
            r = requests.get(url, headers=self.headers_vt, timeout=15)
            if r.status_code == 404:
                return None
            if r.status_code == 429:
                return None
            r.raise_for_status()
            return r.json().get("data", {}).get("attributes", {})
        except Exception:
            return None

    def urlscan_search_domain(self, domain: str, limit=30):
        """Search urlscan for domain occurrences with better error handling"""
        base = "https://urlscan.io/api/v1/search/"
        params = {"q": f"domain:{domain}", "size": limit}
        
        try:
            r = requests.get(base, params=params, timeout=20)
            if r.status_code != 200:
                if r.status_code == 429:
                    print("    ⚠️ URLScan rate limited")
                return []
                
            j = r.json()
            hits = []
            for h in j.get("results", [])[:limit]:  # Hard limit
                task = h.get("task", {})
                page = h.get("page", {})
                hits.append({
                    "task_id": task.get("id"),
                    "url": task.get("url"),
                    "ip": page.get("ip"),
                    "server": page.get("server"),
                })
            return hits
            
        except Exception as ex:
            print(f"    ⚠️ URLScan error: {ex}")
            return []

    def securitytrails_subdomains(self, domain: str):
        if not self.securitytrails_key:
            return []
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": self.securitytrails_key}
            r = requests.get(url, headers=headers, timeout=15)
            if r.status_code == 429:
                print("    ⚠️ SecurityTrails rate limited")
                return []
            r.raise_for_status()
            j = r.json()
            subs = j.get("subdomains", [])
            return [f"{s}.{domain}" for s in subs[:20]]  # Limit subdomains
        except Exception as ex:
            print(f"    ⚠️ SecurityTrails error: {ex}")
            return []

    # -----------------------------
    # Utilities
    # -----------------------------
    def normalize_candidate(self, raw: str):
        """Normalize candidate domain/url"""
        raw = (raw or "").strip()
        if raw.startswith("http"):
            try:
                p = urlparse(raw)
                host = p.netloc.lower()
                return raw, host
            except:
                return raw, raw.lower()
        else:
            host = raw.lower()
            host = host.rstrip('.')
            # Skip very long domains
            if len(host) > 100:
                return host, host
            try:
                if any(ord(c) > 127 for c in host):
                    puny = self.to_punycode(host)
                    return host, puny.lower()
                else:
                    return host, host
            except Exception:
                return host, host

    def fuzzy_distance(self, a: str, b: str):
        """Calculate fuzzy distance between strings"""
        if len(a) > 50 or len(b) > 50:  # Skip for very long strings
            return len(a)  # Return max distance
        a = a.lower(); b = b.lower()
        if HAS_RAPIDFUZZ:
            return Levenshtein.distance(a, b)
        else:
            # Simple DP implementation for fallback
            la, lb = len(a), len(b)
            dp = [[0]*(lb+1) for _ in range(la+1)]
            for i in range(la+1): dp[i][0] = i
            for j in range(lb+1): dp[0][j] = j
            for i in range(1, la+1):
                for j in range(1, lb+1):
                    cost = 0 if a[i-1]==b[j-1] else 1
                    dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
            return dp[la][lb]

    # -----------------------------
    # Scoring & discovery pipeline
    # -----------------------------
    def score_candidate(self, vt_attrs=None, urlscan_hits=False, whois_created=None, 
                       fuzzy_sim=None, has_puny=False, found_in_feeds=False):
        """Score candidate based on multiple factors"""
        score = 0
        if vt_attrs:
            stats = vt_attrs.get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                score += 50
            if stats.get("suspicious", 0) > 0:
                score += 25
        if urlscan_hits:
            score += 10
        if found_in_feeds:
            score += 40
        if fuzzy_sim is not None:
            if fuzzy_sim == 0:
                score += 5
            elif fuzzy_sim <= 2:
                score += 15
        if whois_created:
            try:
                dt = dateparse.parse(whois_created)
                age_days = (datetime.utcnow() - dt).days
                if age_days < 30:
                    score += 20
                elif age_days < 180:
                    score += 5
            except Exception:
                pass
        if has_puny:
            score += 10
        return score

    def discover_domains(self, target_banks=None, max_iterations=1, use_fuzzy=True):
        """
        Main discovery method - finds domains related to target banks
        """
        if target_banks is None:
            # Use banks from config
            target_banks = [bank["short_name"] for bank in self.config.get("known_banks", [])]
        
        print(f"🔍 Starting domain discovery for: {target_banks}")
        
        all_results = {}
        
        for bank_token in target_banks:
            print(f"\n🎯 Discovering domains for: {bank_token}")
            bank_results = self._discover_for_token(bank_token, max_iterations, use_fuzzy)
            all_results.update(bank_results)
            print(f"  ✅ Found {len(bank_results)} domains for {bank_token}")
        
        print(f"✅ Discovery completed: {len(all_results)} total domains found")
        return all_results

    def quick_discover(self, target_banks=None):
        """Quick discovery using only reliable sources"""
        if target_banks is None:
            target_banks = [bank["short_name"] for bank in self.config.get("known_banks", [])]
        
        print("⚡ Starting quick domain discovery...")
        all_results = {}
        
        for bank_token in target_banks:
            print(f"🎯 Quick discovery for: {bank_token}")
            bank_results = {}
            
            # Only use main variants for quick mode
            variants = set([bank_token])
            variants.add(f"www.{bank_token}")
            variants.add(f"login.{bank_token}")
            variants.add(f"secure.{bank_token}")
            variants.add(f"online.{bank_token}")
            
            for variant in variants:
                try:
                    # URLScan only (most reliable)
                    urlscan_hits = self.urlscan_search_domain(variant, limit=20)
                    for hit in urlscan_hits:
                        url = hit.get("url")
                        if url:
                            raw, host = self.normalize_candidate(url)
                            if host and len(host) < 100:  # Reasonable length
                                if host not in bank_results:
                                    bank_results[host] = {
                                        "sources": set(["URLScan"]),
                                        "raws": set([raw]),
                                        "score": 10,
                                        "host": host,
                                        "urlscan": [hit]
                                    }
                    
                    # Add basic typos for main token only
                    if variant == bank_token:
                        basic_typos = self.gen_typos(bank_token)
                        for typo in list(basic_typos)[:3]:  # Only 3 typos
                            urlscan_hits = self.urlscan_search_domain(typo, limit=10)
                            for hit in urlscan_hits:
                                url = hit.get("url")
                                if url:
                                    raw, host = self.normalize_candidate(url)
                                    if host and len(host) < 100:
                                        if host not in bank_results:
                                            bank_results[host] = {
                                                "sources": set(["URLScan"]),
                                                "raws": set([raw]),
                                                "score": 15,  # Higher score for typos
                                                "host": host,
                                                "urlscan": [hit]
                                            }
                
                except Exception as e:
                    print(f"  ⚠️ Error in quick discovery: {e}")
                    continue
                
                time.sleep(0.5)  # Rate limiting
            
            all_results.update(bank_results)
            print(f"  ✅ Found {len(bank_results)} domains for {bank_token}")
        
        return all_results

    def _discover_for_token(self, seed_token: str, max_iterations=1, use_fuzzy=True):
        """Discover domains for a single token with improved error handling"""
        seed = seed_token.lower().strip()
        discovered = {}
        queue = set([seed])
        processed = set()
        iteration = 0

        while queue and iteration < max_iterations:
            iteration += 1
            print(f"  🔄 Iteration {iteration}, processing {len(queue)} tokens")
            next_queue = set()
            
            for token in list(queue):
                if token in processed:
                    continue
                processed.add(token)
                
                print(f"    Processing: {token}")
                
                # Generate limited variants
                variants = set([token])
                if use_fuzzy and len(token) <= 15:  # Only fuzzy for short tokens
                    try:
                        variants |= self.gen_typos(token)
                        variants |= self.gen_homoglyphs(token)
                    except Exception as e:
                        print(f"    ⚠️ Variant generation error: {e}")
                
                # Strict variant limiting
                variants = set(list(variants)[:50])  # Hard limit
                
                for v in variants:
                    try:
                        # Certificate Transparency with fallback
                        crt_domains = self.query_crtsh_for_token(v)
                        if not crt_domains and len(v) > 3:
                            crt_domains = self.query_alternate_ct_sources(v)
                            
                        for d in crt_domains:
                            self._add_discovered_domain(d, "crt.sh", discovered, next_queue, processed)

                        # VirusTotal (limited)
                        if self.vt_api_key:
                            vt_domains = self.vt_search(f"type:domain {v}", limit=10)
                            vt_urls = self.vt_search(f"type:url {v}", limit=10)
                            for h in set(vt_domains + vt_urls):
                                self._add_discovered_domain(h, "VirusTotal", discovered, next_queue, processed)

                        # URLScan
                        urlscan_hits = self.urlscan_search_domain(v, limit=15)
                        for hit in urlscan_hits:
                            url = hit.get("url")
                            if url:
                                self._add_discovered_domain(url, "URLScan", discovered, next_queue, processed)

                        # SecurityTrails
                        if self.securitytrails_key and '.' in v and len(v) < 30:
                            st_subs = self.securitytrails_subdomains(v)
                            for sub in st_subs:
                                self._add_discovered_domain(sub, "SecurityTrails", discovered, next_queue, processed)
                                
                    except Exception as e:
                        print(f"    ❌ Error processing variant {v}: {e}")
                        continue
                    
                    time.sleep(0.3)  # Conservative rate limiting

            queue = {q for q in next_queue if q not in processed and len(discovered) < 1000}  # Overall limit

        # Enrich discovered domains
        return self._enrich_discovered_domains(discovered, seed)

    def _add_discovered_domain(self, raw_domain: str, source: str, discovered: dict, 
                             next_queue: set, processed: set):
        """Add discovered domain to results"""
        raw, host = self.normalize_candidate(raw_domain)
        if not host or len(host) < 3 or len(host) > 100:
            return
            
        meta = discovered.setdefault(host, {
            "sources": set(), 
            "raws": set(), 
            "scores": [], 
            "vt": None, 
            "urlscan": [], 
            "whois_created": None
        })
        meta["sources"].add(source)
        meta["raws"].add(raw)
        
        # Queue for expansion if new and reasonable
        if host not in processed and len(host) < 50:
            next_queue.add(host)

    def _enrich_discovered_domains(self, discovered: dict, seed_token: str):
        """Enrich discovered domains with additional data"""
        enriched = {}
        
        for host, meta in discovered.items():
            # Skip if host is too long
            if len(host) > 100:
                continue
                
            # Check punycode
            has_puny = host.startswith("xn--") or any(ord(c) > 127 for c in host)
            
            # VT domain report
            vt_attrs = None
            try:
                vt_attrs = self.vt_domain_report(host) if self.vt_api_key else None
                meta["vt"] = vt_attrs
            except Exception:
                meta["vt"] = None
                
            # URLScan hits
            us_hits = bool(meta.get("urlscan"))
            
            # WHOIS data
            created = None
            if meta.get("vt"):
                created = meta["vt"].get("registered_date") or meta["vt"].get("creation_date")
                meta["whois_created"] = created
            
            # Fuzzy distance
            try:
                edit = self.fuzzy_distance(host.split('.')[0], seed_token)
            except Exception:
                edit = None
                
            # Score
            score = self.score_candidate(
                vt_attrs=meta.get("vt"), 
                urlscan_hits=us_hits, 
                whois_created=created, 
                fuzzy_sim=edit, 
                has_puny=has_puny
            )
            
            meta["score"] = score
            meta["fuzzy_dist"] = edit
            meta["host"] = host
            meta["seed_token"] = seed_token
            
            enriched[host] = meta
            
        return enriched

    def save_discovery_results(self, results, filename="discovered_domains.csv"):
        """Save discovery results to CSV"""
        rows = []
        for host, meta in sorted(results.items(), key=lambda x: -x[1].get("score", 0)):
            rows.append({
                "host": host,
                "score": meta.get("score"),
                "sources": "|".join(sorted(meta.get("sources", []))),
                "seed_token": meta.get("seed_token", ""),
                "example_raw": next(iter(meta.get("raws", []))) if meta.get("raws") else "",
                "vt_malicious": (meta.get("vt", {}).get("last_analysis_stats", {}).get("malicious") if meta.get("vt") else ""),
                "urlscan_hits": len(meta.get("urlscan", [])),
                "whois_created": meta.get("whois_created"),
                "fuzzy_dist": meta.get("fuzzy_dist")
            })
        
        df = pd.DataFrame(rows)
        df.to_csv(filename, index=False)
        print(f"💾 Discovery results saved to: {filename}")
        return filename

    def get_high_risk_domains(self, results, threshold=30):
        """Get high-risk domains based on score threshold"""
        return {host: meta for host, meta in results.items() 
                if meta.get("score", 0) >= threshold}

# For standalone testing
if __name__ == "__main__":
    discovery = DomainDiscovery()
    print("Testing quick discovery...")
    results = discovery.quick_discover(["sbi", "hdfc"])
    discovery.save_discovery_results(results, "quick_discovery_test.csv")
    print(f"Found {len(results)} domains")