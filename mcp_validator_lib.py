#!/usr/bin/env python3
"""
MCP Server Security Validation Agent

This agent TESTS THE SERVER's security controls by using multiple client
configurations to validate that the server properly enforces:

1. Authentication (rejects anonymous, invalid tokens, accepts valid tokens)
2. HTTPS enforcement (rejects HTTP, requires HTTPS)
3. HTTP method security (rejects GET for tool invocation)
4. Rate limiting (throttles excessive requests)
5. Security headers (includes proper headers)
6. TLS configuration (uses strong protocols)
7. Error handling (doesn't leak information)

Usage:
    python3 mcp_server_security_validator.py --server my_server
    python3 mcp_server_security_validator.py --all
"""

import argparse
import json
import os
import sys
import time
import requests
import ssl
import socket
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
from pathlib import Path


# ==============================================================================
# SERVER SECURITY VALIDATOR
# ==============================================================================

class MCPServerSecurityValidator:
    """Validates MCP server security controls using multiple test configurations."""
    
    def __init__(self, server_name: str, server_config: Dict[str, Any], verbose: bool = False):
        self.server_name = server_name
        self.server_config = server_config
        self.verbose = verbose
        
        # Parse configuration
        self.transport = server_config.get('type', 'http')
        self.url = server_config.get('url', '')
        self.valid_token = self._extract_valid_token(server_config)
        
        # Test results
        self.results = {
            'server_name': server_name,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'url': self.url,
            'protocol_version': None,
            'server_info': {},
            'tests': {}
        }
    
    def _extract_valid_token(self, config: Dict[str, Any]) -> Optional[str]:
        """Extract valid authentication token from config if present."""
        headers = config.get('headers', {})
        auth_header = headers.get('Authorization', '')
        
        if auth_header and not auth_header.startswith('${'):
            # Extract token
            return auth_header.replace('Bearer ', '').replace('bearer ', '').strip()
        
        # Try environment variables
        env_vars = [
            f"{self.server_name.upper()}_TOKEN",
            f"{self.server_name.upper().replace('_MCP_SERVER', '')}_TOKEN",
            "MCP_TOKEN"
        ]
        
        for var in env_vars:
            token = os.environ.get(var)
            if token:
                return token
        
        return None
    
    def log(self, message: str, level: str = 'info'):
        """Log message with formatting."""
        symbols = {
            'info': 'ℹ️ ',
            'success': '✅',
            'warning': '⚠️ ',
            'error': '❌',
            'critical': '🔴',
            'test': '🧪',
            'security': '🛡️'
        }
        symbol = symbols.get(level, '•')
        
        if self.verbose or level in ['success', 'warning', 'error', 'critical', 'security']:
            print(f"{symbol} {message}")
    
    def detect_protocol_version(self):
        """Detect MCP protocol version from server."""
        self.log("Detecting MCP protocol version...", 'info')
        
        try:
            # Send initialize request with valid token if available
            headers = {}
            if self.valid_token:
                headers['Authorization'] = f'Bearer {self.valid_token}'
            
            response = requests.post(
                f"{self.url}/initialize",
                json={
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcp-security-validator",
                        "version": "1.0.0"
                    }
                },
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract protocol version
                if 'protocolVersion' in data:
                    self.results['protocol_version'] = data['protocolVersion']
                    print(f"📋 MCP Protocol Version: {data['protocolVersion']}")
                
                # Extract server info
                if 'serverInfo' in data:
                    self.results['server_info'] = data['serverInfo']
                    server_name = data['serverInfo'].get('name', 'Unknown')
                    server_version = data['serverInfo'].get('version', 'Unknown')
                    print(f"🖥️  Server: {server_name} v{server_version}")
                
                # Extract capabilities
                if 'capabilities' in data:
                    caps = data['capabilities']
                    cap_list = []
                    if caps.get('tools'):
                        cap_list.append('tools')
                    if caps.get('resources'):
                        cap_list.append('resources')
                    if caps.get('prompts'):
                        cap_list.append('prompts')
                    if cap_list:
                        print(f"⚙️  Capabilities: {', '.join(cap_list)}")
                
                self.log("Protocol version detected", 'success')
                
            elif response.status_code in [401, 403]:
                self.log("Authentication required for protocol detection", 'info')
                print(f"🔒 Authentication required (HTTP {response.status_code})")
            else:
                self.log(f"Could not detect protocol version (HTTP {response.status_code})", 'warning')
                
        except requests.exceptions.JSONDecodeError:
            self.log("Server response is not valid JSON", 'warning')
        except Exception as e:
            self.log(f"Protocol detection failed: {str(e)[:100]}", 'warning')
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all server security validation tests."""
        print(f"\n{'='*70}")
        print(f"🛡️  MCP SERVER SECURITY VALIDATOR")
        print(f"{'='*70}")
        print(f"Server: {self.server_name}")
        print(f"URL: {self.url}")
        print(f"Testing: Server-side security controls")
        print(f"{'='*70}\n")
        
        # Only test HTTP/HTTPS servers
        if self.transport not in ['http', 'https']:
            self.log(f"Skipping - only HTTP/HTTPS transports supported", 'warning')
            return self.results
        
        # Detect protocol version first
        self.detect_protocol_version()
        print()
        
        # Run validation tests
        try:
            self.test_authentication_enforcement()
            self.test_https_enforcement()
            self.test_http_method_enforcement()
            self.test_rate_limiting_enforcement()
            self.test_tls_configuration()
            self.test_security_headers()
            self.test_error_handling()
            
            # Calculate score
            self.calculate_security_score()
            
            # Print detailed report
            if self.verbose:
                self.print_detailed_report()
            
        except Exception as e:
            self.log(f"Error during testing: {e}", 'error')
            self.results['error'] = str(e)
        
        return self.results
    
    def test_authentication_enforcement(self):
        """
        TEST 1: Authentication Enforcement
        Validates that the server properly enforces authentication.
        """
        print("\n🔐 TEST 1: Authentication Enforcement (Server-Side)")
        print("-" * 70)
        
        findings = []
        severity = 'LOW'
        
        # Test 1.1: Anonymous Access (NO TOKEN)
        self.log("Testing if server rejects anonymous requests...", 'test')
        try:
            response = requests.post(
                f"{self.url}/initialize",
                json={"protocolVersion": "2024-11-05", "capabilities": {}},
                timeout=10
            )
            
            if response.status_code in [401, 403]:
                findings.append(f"✅ PASS: Anonymous access rejected (HTTP {response.status_code})")
                self.log("Server properly rejects anonymous requests", 'success')
            elif response.status_code == 200:
                findings.append(f"🔴 FAIL: Anonymous access allowed - CRITICAL SECURITY FLAW")
                severity = 'CRITICAL'
                self.log("Server accepts anonymous requests - NO AUTHENTICATION!", 'critical')
            else:
                findings.append(f"⚠️  INCONCLUSIVE: Unexpected status {response.status_code}")
                severity = 'MEDIUM'
        except Exception as e:
            findings.append(f"Error testing anonymous access: {str(e)[:100]}")
        
        # Test 1.2: Invalid Token
        self.log("Testing if server rejects invalid tokens...", 'test')
        invalid_tokens = [
            "INVALID_TOKEN_12345",
            "Bearer FAKE_TOKEN",
            "malformed.jwt.token",
            "../../etc/passwd",
            "<script>alert('xss')</script>"
        ]
        
        invalid_rejected = 0
        for invalid_token in invalid_tokens:
            try:
                response = requests.post(
                    f"{self.url}/initialize",
                    json={"protocolVersion": "2024-11-05", "capabilities": {}},
                    headers={"Authorization": f"Bearer {invalid_token}"},
                    timeout=10
                )
                
                if response.status_code in [401, 403]:
                    invalid_rejected += 1
                elif response.status_code == 200:
                    findings.append(f"🔴 FAIL: Invalid token accepted: {invalid_token[:20]}...")
                    severity = 'CRITICAL'
                    self.log(f"Server accepted invalid token!", 'critical')
                    break
            except:
                pass
        
        if invalid_rejected == len(invalid_tokens):
            findings.append(f"✅ PASS: All {len(invalid_tokens)} invalid tokens rejected")
            self.log("Server properly validates tokens", 'success')
        elif invalid_rejected > 0:
            findings.append(f"⚠️  PARTIAL: {invalid_rejected}/{len(invalid_tokens)} invalid tokens rejected")
            if severity != 'CRITICAL':
                severity = 'HIGH'
        
        # Test 1.3: Valid Token (if available)
        if self.valid_token:
            self.log("Testing if server accepts valid token...", 'test')
            try:
                response = requests.post(
                    f"{self.url}/initialize",
                    json={"protocolVersion": "2024-11-05", "capabilities": {}},
                    headers={"Authorization": f"Bearer {self.valid_token}"},
                    timeout=10
                )
                
                if response.status_code == 200:
                    findings.append(f"✅ PASS: Valid token accepted (OAuth2 working correctly)")
                    self.log("Server accepts valid OAuth2 token", 'success')
                elif response.status_code in [401, 403]:
                    findings.append(f"⚠️  WARNING: Valid token rejected - check token validity")
                    if severity == 'LOW':
                        severity = 'MEDIUM'
                else:
                    findings.append(f"⚠️  Unexpected response with valid token: {response.status_code}")
            except Exception as e:
                findings.append(f"Error testing valid token: {str(e)[:100]}")
        else:
            findings.append("ℹ️  No valid token provided - cannot test valid authentication")
        
        # Test 1.4: Token format validation
        self.log("Testing if server validates OAuth2 token format...", 'test')
        malformed_formats = [
            "",  # Empty
            "Bearer ",  # No token
            "InvalidFormat xyz123",  # Wrong format
        ]
        
        format_checks = 0
        for malformed in malformed_formats:
            try:
                response = requests.post(
                    f"{self.url}/initialize",
                    json={"protocolVersion": "2024-11-05", "capabilities": {}},
                    headers={"Authorization": malformed} if malformed else {},
                    timeout=10
                )
                
                if response.status_code in [400, 401, 403]:
                    format_checks += 1
            except:
                pass
        
        if format_checks == len(malformed_formats):
            findings.append(f"✅ PASS: Server validates OAuth2 token format")
        
        self.results['tests']['authentication_enforcement'] = {
            'severity': severity,
            'findings': findings,
            'has_authentication': severity != 'CRITICAL'
        }
        
        print(f"  Result: {severity}")
        for finding in findings:
            print(f"  • {finding}")
    
    def test_https_enforcement(self):
        """
        TEST 2: HTTPS Enforcement
        Validates that the server enforces HTTPS and rejects/redirects HTTP.
        """
        print("\n🔒 TEST 2: HTTPS Enforcement (Server-Side)")
        print("-" * 70)
        
        findings = []
        severity = 'LOW'
        
        parsed_url = urlparse(self.url)
        
        if parsed_url.scheme == 'https':
            findings.append("✅ Server configured to use HTTPS")
            self.log("Server uses HTTPS", 'success')
            
            # Test if HTTP is properly handled
            http_url = self.url.replace('https://', 'http://')
            self.log(f"Testing if server rejects/redirects HTTP...", 'test')
            
            try:
                response = requests.get(
                    http_url,
                    timeout=5,
                    allow_redirects=False,
                    verify=False
                )
                
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    if location.startswith('https://'):
                        findings.append(f"✅ PASS: Server redirects HTTP to HTTPS (HTTP {response.status_code})")
                        self.log("Server properly redirects HTTP to HTTPS", 'success')
                    else:
                        findings.append(f"⚠️  WARNING: Redirect but not to HTTPS: {location}")
                        severity = 'MEDIUM'
                elif response.status_code >= 400:
                    findings.append(f"✅ PASS: Server denies HTTP requests (HTTP {response.status_code})")
                    self.log("Server rejects HTTP requests", 'success')
                else:
                    findings.append(f"🔴 FAIL: Server accepts HTTP without redirect - CRITICAL")
                    severity = 'CRITICAL'
                    self.log("Server accepts unencrypted HTTP!", 'critical')
                    
            except requests.exceptions.ConnectionError:
                findings.append("✅ PASS: HTTP port not accessible (connection refused)")
                self.log("HTTP port blocked", 'success')
            except requests.exceptions.SSLError:
                findings.append("✅ PASS: HTTP properly blocked by SSL enforcement")
            except Exception as e:
                findings.append(f"HTTP test inconclusive: {str(e)[:100]}")
        
        elif parsed_url.scheme == 'http':
            findings.append("🔴 FAIL: Server uses unencrypted HTTP - CRITICAL FLAW")
            findings.append("All data transmitted in plaintext")
            severity = 'CRITICAL'
            self.log("Server does not use HTTPS!", 'critical')
        
        self.results['tests']['https_enforcement'] = {
            'severity': severity,
            'findings': findings,
            'uses_https': parsed_url.scheme == 'https'
        }
        
        print(f"  Result: {severity}")
        for finding in findings:
            print(f"  • {finding}")
    
    def test_http_method_enforcement(self):
        """
        TEST 3: HTTP Method Enforcement
        Validates that server only accepts POST for tool invocation (prevents CSRF).
        """
        print("\n🚫 TEST 3: HTTP Method Enforcement (Server-Side)")
        print("-" * 70)
        
        findings = []
        severity = 'LOW'
        
        # Test POST (should work or return auth error)
        self.log("Testing POST method (should be accepted)...", 'test')
        try:
            response = requests.post(
                f"{self.url}/tools/list",
                json={},
                timeout=10
            )
            post_status = response.status_code
            
            if post_status in [200, 401, 403]:
                findings.append(f"✅ PASS: Server accepts POST method (HTTP {post_status})")
                self.log("POST method accepted", 'success')
            else:
                findings.append(f"⚠️  POST returned unexpected status: {post_status}")
        except Exception as e:
            findings.append(f"POST test error: {str(e)[:50]}")
            post_status = 0
        
        # Test GET (should be rejected with 405 or auth-protected with 401/403)
        self.log("Testing GET method (should be rejected)...", 'test')
        try:
            response = requests.get(
                f"{self.url}/tools/list",
                timeout=10
            )
            get_status = response.status_code
            
            if get_status == 405:
                findings.append(f"✅ PASS: Server rejects GET with 405 Method Not Allowed")
                self.log("GET properly rejected", 'success')
            elif get_status in [401, 403]:
                findings.append(f"✅ PASS: Server requires auth for GET (HTTP {get_status}) - CSRF protected")
                self.log("GET auth-protected", 'success')
            elif get_status == 200:
                findings.append(f"🔴 FAIL: Server accepts GET - CSRF VULNERABILITY")
                severity = 'CRITICAL'
                self.log("Server accepts GET requests - CSRF risk!", 'critical')
            else:
                findings.append(f"⚠️  GET returned status: {get_status}")
        except Exception as e:
            findings.append(f"GET test inconclusive: {str(e)[:50]}")
        
        # Test tool invocation endpoints
        self.log("Testing tool invocation endpoints...", 'test')
        test_endpoints = [
            f"{self.url}/tools/call?tool=test",
            f"{self.url}/call?name=test",
            f"{self.url}/invoke?tool=test"
        ]
        
        csrf_vulnerable = False
        for endpoint in test_endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                # Safe status codes: 404 (not found), 405 (method not allowed), 401/403 (auth required)
                if response.status_code not in [401, 403, 404, 405]:
                    response_text = response.text.lower()
                    # Additional check: if response explicitly says method not allowed or not found
                    if 'method not allowed' not in response_text and 'not found' not in response_text:
                        # Only flag if status is 2xx (successful) - this is a true CSRF vulnerability
                        if 200 <= response.status_code < 300:
                            findings.append(f"🔴 FAIL: GET tool invocation at {endpoint} - CSRF!")
                            severity = 'CRITICAL'
                            csrf_vulnerable = True
                            self.log(f"CSRF vulnerability at {endpoint}", 'critical')
                            break
            except:
                pass
        
        if not csrf_vulnerable:
            findings.append("✅ PASS: Tool invocation via GET properly blocked")
        
        self.results['tests']['http_method_enforcement'] = {
            'severity': severity,
            'findings': findings,
            'post_accepted': post_status in [200, 401, 403],
            'get_rejected': not csrf_vulnerable
        }
        
        print(f"  Result: {severity}")
        for finding in findings:
            print(f"  • {finding}")
    
    def test_rate_limiting_enforcement(self):
        """
        TEST 4: Rate Limiting Enforcement
        Validates that server implements rate limiting.
        """
        print("\n⏱️  TEST 4: Rate Limiting Enforcement (Server-Side)")
        print("-" * 70)
        
        findings = []
        severity = 'LOW'
        
        self.log("Sending rapid requests to test rate limiting...", 'test')
        
        rate_limited = False
        successful_requests = 0
        start_time = time.time()
        
        # Send 50 rapid requests
        for i in range(50):
            try:
                response = requests.post(
                    f"{self.url}/tools/list",
                    json={},
                    timeout=5
                )
                
                if response.status_code == 429:
                    rate_limited = True
                    findings.append(f"✅ PASS: Rate limiting enforced at request {i+1} (HTTP 429)")
                    self.log(f"Rate limiting detected after {i+1} requests", 'success')
                    break
                elif response.status_code in [200, 401, 403]:
                    successful_requests += 1
            except Exception as e:
                if '429' in str(e) or 'rate' in str(e).lower():
                    rate_limited = True
                    findings.append(f"✅ PASS: Rate limiting detected (connection refused)")
                    break
        
        elapsed = time.time() - start_time
        
        if not rate_limited:
            findings.append(f"🔴 FAIL: No rate limiting detected ({successful_requests} requests in {elapsed:.2f}s)")
            findings.append("Server vulnerable to DoS attacks")
            severity = 'HIGH'
            self.log("No rate limiting found", 'critical')
        
        findings.append(f"Request rate: {successful_requests/elapsed:.1f} requests/second")
        
        self.results['tests']['rate_limiting_enforcement'] = {
            'severity': severity,
            'findings': findings,
            'rate_limited': rate_limited,
            'requests_before_limit': successful_requests if rate_limited else successful_requests
        }
        
        print(f"  Result: {severity}")
        for finding in findings:
            print(f"  • {finding}")
    
    def test_tls_configuration(self):
        """
        TEST 5: TLS Configuration
        Validates TLS version and certificate.
        """
        print("\n🔐 TEST 5: TLS Configuration (Server-Side)")
        print("-" * 70)
        
        findings = []
        severity = 'LOW'
        
        parsed_url = urlparse(self.url)
        
        if parsed_url.scheme != 'https':
            findings.append("TLS not applicable (HTTP connection)")
            self.results['tests']['tls_configuration'] = {
                'severity': 'N/A',
                'findings': findings
            }
            print("  Result: N/A (HTTP)")
            return
        
        self.log("Checking TLS configuration...", 'test')
        
        try:
            # Test certificate validation using requests (uses certifi CA bundle - more reliable)
            try:
                response = requests.get(self.url, timeout=5, verify=True)
                findings.append(f"✅ PASS: Valid TLS certificate")
                self.log("Certificate valid", 'success')
                
                # Try to get TLS version info using ssl module with certifi
                try:
                    import certifi
                    hostname = parsed_url.hostname
                    port = parsed_url.port or 443
                    context = ssl.create_default_context(cafile=certifi.where())
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            tls_version = ssock.version()
                            cipher = ssock.cipher()
                            
                            findings.append(f"✅ TLS Version: {tls_version}")
                            
                            if tls_version in ['TLSv1.3', 'TLSv1.2']:
                                findings.append(f"✅ PASS: Strong TLS protocol in use")
                                self.log(f"Strong TLS: {tls_version}", 'success')
                            else:
                                findings.append(f"🔴 FAIL: Weak TLS version: {tls_version}")
                                severity = 'CRITICAL'
                                self.log("Weak TLS detected", 'critical')
                            
                            findings.append(f"Cipher: {cipher[0]}")
                except ImportError:
                    # certifi not available, skip detailed TLS info
                    findings.append(f"ℹ️  TLS version info not available (certifi not installed)")
                except:
                    # TLS version check failed, but cert is valid
                    pass
                    
            except requests.exceptions.SSLError as ssl_err:
                # Genuine SSL error from requests
                findings.append(f"🔴 FAIL: Certificate verification failed")
                findings.append(f"Error: {str(ssl_err)[:150]}")
                severity = 'HIGH'
                self.log("Certificate verification failed", 'error')
                
        except Exception as e:
            findings.append(f"TLS test error: {str(e)[:100]}")
            severity = 'HIGH'
        
        self.results['tests']['tls_configuration'] = {
            'severity': severity,
            'findings': findings
        }
        
        print(f"  Result: {severity}")
        for finding in findings:
            print(f"  • {finding}")
    
    def test_security_headers(self):
        """
        TEST 6: Security Headers
        Validates that server includes security headers.
        """
        print("\n🛡️  TEST 6: Security Headers (Server-Side)")
        print("-" * 70)
        
        findings = []
        severity = 'LOW'
        
        self.log("Checking security headers...", 'test')
        
        try:
            response = requests.get(self.url, timeout=10)
            headers = response.headers
            
            # Required security headers
            security_headers = {
                'Strict-Transport-Security': ('HSTS', 'Forces HTTPS'),
                'X-Content-Type-Options': ('MIME sniffing protection', 'Prevents MIME sniffing'),
                'X-Frame-Options': ('Clickjacking protection', 'Prevents clickjacking'),
                'Content-Security-Policy': ('XSS protection', 'Prevents XSS attacks'),
                'X-XSS-Protection': ('Browser XSS filter', 'Browser XSS protection')
            }
            
            present_count = 0
            for header, (name, description) in security_headers.items():
                if header in headers:
                    present_count += 1
                    findings.append(f"✅ {header} present: {description}")
                else:
                    findings.append(f"⚠️  {header} missing: {description}")
            
            if present_count >= 4:
                findings.insert(0, f"✅ PASS: {present_count}/5 security headers present")
                self.log(f"{present_count}/5 security headers found", 'success')
            elif present_count >= 2:
                findings.insert(0, f"⚠️  PARTIAL: Only {present_count}/5 security headers present")
                severity = 'MEDIUM'
                self.log("Missing security headers", 'warning')
            else:
                findings.insert(0, f"🔴 FAIL: Only {present_count}/5 security headers present")
                severity = 'HIGH'
                self.log("Critical security headers missing", 'error')
            
        except Exception as e:
            findings.append(f"Security headers test error: {str(e)[:100]}")
            severity = 'MEDIUM'
        
        self.results['tests']['security_headers'] = {
            'severity': severity,
            'findings': findings
        }
        
        print(f"  Result: {severity}")
        for finding in findings:
            print(f"  • {finding}")
    
    def test_error_handling(self):
        """
        TEST 7: Error Handling
        Validates that server doesn't leak information in errors.
        """
        print("\n🐛 TEST 7: Error Handling (Server-Side)")
        print("-" * 70)
        
        findings = []
        severity = 'LOW'
        
        self.log("Testing error handling...", 'test')
        
        # Test with various malformed requests
        test_cases = [
            ("Invalid JSON", "NOT_JSON{{{"),
            ("SQL injection attempt", "'; DROP TABLE users; --"),
            ("Path traversal", "../../../etc/passwd"),
            ("XSS attempt", "<script>alert('xss')</script>"),
            ("Command injection", "; ls -la; whoami")
        ]
        
        info_disclosed = False
        
        for test_name, payload in test_cases:
            try:
                response = requests.post(
                    f"{self.url}/initialize",
                    data=payload,
                    timeout=5
                )
                
                response_text = response.text.lower()
                
                # Check for information disclosure
                disclosure_indicators = [
                    ('traceback', 'Stack trace'),
                    ('file "/', 'File path'),
                    ('line ', 'Line numbers'),
                    ('exception', 'Exception details'),
                    ('error at', 'Error location'),
                    ('c:\\', 'Windows path'),
                    ('/usr/', 'Unix path'),
                    ('/var/', 'System path')
                ]
                
                for indicator, description in disclosure_indicators:
                    if indicator in response_text:
                        findings.append(f"🔴 FAIL: {description} leaked in {test_name}")
                        info_disclosed = True
                        severity = 'MEDIUM'
                        self.log(f"Information disclosure: {description}", 'warning')
                        break
                        
            except:
                pass
        
        if not info_disclosed:
            findings.append("✅ PASS: No information disclosure detected in error messages")
            self.log("Error handling secure", 'success')
        else:
            findings.append("⚠️  Server leaks internal information in errors")
        
        self.results['tests']['error_handling'] = {
            'severity': severity,
            'findings': findings,
            'info_disclosed': info_disclosed
        }
        
        print(f"  Result: {severity}")
        for finding in findings:
            print(f"  • {finding}")
    
    def calculate_security_score(self):
        """Calculate overall security score based on test results."""
        severity_scores = {
            'CRITICAL': 0,
            'HIGH': 25,
            'MEDIUM': 50,
            'LOW': 100,
            'N/A': None
        }
        
        scores = []
        score_breakdown = []
        
        for test_name, test_result in self.results['tests'].items():
            severity = test_result.get('severity')
            if severity and severity != 'N/A':
                test_score = severity_scores[severity]
                scores.append(test_score)
                score_breakdown.append({
                    'test': test_name,
                    'severity': severity,
                    'score': test_score
                })
        
        if scores:
            avg_score = sum(scores) / len(scores)
            self.results['overall_security_score'] = round(avg_score, 2)
            self.results['score_breakdown'] = score_breakdown
            
            if avg_score >= 80:
                self.results['security_rating'] = 'EXCELLENT'
            elif avg_score >= 60:
                self.results['security_rating'] = 'GOOD'
            elif avg_score >= 40:
                self.results['security_rating'] = 'FAIR'
            elif avg_score >= 20:
                self.results['security_rating'] = 'POOR'
            else:
                self.results['security_rating'] = 'CRITICAL'
    
    def print_detailed_report(self):
        """Print a beautiful, detailed security report."""
        score = self.results.get('overall_security_score', 0)
        rating = self.results.get('security_rating', 'N/A')
        
        # Rating emoji and color
        rating_display = {
            'EXCELLENT': ('🟢', 'EXCELLENT'),
            'GOOD': ('🟢', 'GOOD'),
            'FAIR': ('🟡', 'FAIR'),
            'POOR': ('🟠', 'POOR'),
            'CRITICAL': ('🔴', 'CRITICAL')
        }.get(rating, ('⚪', 'N/A'))
        
        emoji, rating_text = rating_display
        
        print(f"\n{'='*70}")
        print("📊 FINAL SECURITY ASSESSMENT")
        print(f"{'='*70}\n")
        
        # Overall score with visual bar
        print(f"Server: {self.server_name}")
        print(f"URL: {self.url}")
        
        # Show protocol version if detected
        if self.results.get('protocol_version'):
            print(f"MCP Protocol: {self.results['protocol_version']}")
        if self.results.get('server_info'):
            server_info = self.results['server_info']
            if 'name' in server_info and 'version' in server_info:
                print(f"Server Info: {server_info['name']} v{server_info['version']}")
        
        print(f"Rating: {emoji} {rating_text}")
        print(f"Score: {score}/100")
        
        # Visual score bar
        bar_length = 50
        filled = int((score / 100) * bar_length)
        bar = '█' * filled + '░' * (bar_length - filled)
        print(f"\n[{bar}] {score}%\n")
        
        # Score breakdown
        if 'score_breakdown' in self.results:
            print(f"{'─'*70}")
            print("📋 SCORE BREAKDOWN (Each test weighted equally)")
            print(f"{'─'*70}\n")
            
            breakdown = self.results['score_breakdown']
            
            # Table header
            print(f"{'Test':<35} {'Severity':<12} {'Score':<10} {'Visual'}")
            print(f"{'─'*35} {'─'*12} {'─'*10} {'─'*20}")
            
            for item in breakdown:
                test_name = item['test'].replace('_', ' ').title()
                severity = item['severity']
                test_score = item['score']
                
                # Severity emoji
                severity_emoji = {
                    'LOW': '✅',
                    'MEDIUM': '🟡',
                    'HIGH': '🔴',
                    'CRITICAL': '⚫'
                }.get(severity, '⚪')
                
                # Mini bar for this test
                mini_bar_len = 10
                mini_filled = int((test_score / 100) * mini_bar_len)
                mini_bar = '█' * mini_filled + '░' * (mini_bar_len - mini_filled)
                
                print(f"{test_name:<35} {severity_emoji} {severity:<9} {test_score:>3}/100   [{mini_bar}]")
            
            # Calculation
            total = sum(item['score'] for item in breakdown)
            count = len(breakdown)
            avg = total / count if count > 0 else 0
            
            print(f"{'─'*70}")
            print(f"{'Total':<35} {'':<12} {total:>3}/{count*100:<5} {'Average: ' + str(round(avg, 2))}")
            print(f"{'─'*70}\n")
        
        # Issue summary
        issue_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for test_result in self.results['tests'].values():
            severity = test_result.get('severity')
            if severity in issue_counts:
                if severity != 'LOW':  # Only count issues
                    issue_counts[severity] += 1
        
        print(f"{'─'*70}")
        print("🚨 ISSUE SUMMARY")
        print(f"{'─'*70}\n")
        
        critical = issue_counts['CRITICAL']
        high = issue_counts['HIGH']
        medium = issue_counts['MEDIUM']
        low_issues = issue_counts['LOW']
        
        total_issues = critical + high + medium
        
        if total_issues == 0:
            print("🎉 No security issues found! Excellent work!\n")
        else:
            if critical > 0:
                print(f"⚫ CRITICAL Issues: {critical}  ← URGENT: Immediate action required")
            if high > 0:
                print(f"🔴 HIGH Issues: {high}      ← Fix before production deployment")
            if medium > 0:
                print(f"🟡 MEDIUM Issues: {medium}    ← Should be addressed")
            print()
        
        # Key recommendations
        print(f"{'─'*70}")
        print("💡 KEY RECOMMENDATIONS")
        print(f"{'─'*70}\n")
        
        recommendations = []
        
        for test_name, test_result in self.results['tests'].items():
            severity = test_result.get('severity')
            
            if severity == 'HIGH' or severity == 'CRITICAL':
                if test_name == 'http_method_enforcement':
                    recommendations.append("🔴 Add CSRF protection: Require POST for tool invocations")
                elif test_name == 'rate_limiting':
                    recommendations.append("🔴 Implement rate limiting: Prevent DoS attacks")
                elif test_name == 'authentication_enforcement':
                    recommendations.append("🔴 Fix authentication: Server must reject invalid credentials")
                elif test_name == 'https_enforcement':
                    recommendations.append("🔴 Enforce HTTPS: Redirect or reject HTTP requests")
                elif test_name == 'security_headers':
                    recommendations.append("🔴 Add security headers: HSTS, X-Content-Type-Options, etc.")
            
            elif severity == 'MEDIUM':
                if test_name == 'security_headers':
                    recommendations.append("🟡 Complete security headers: Add missing headers")
                elif test_name == 'error_handling':
                    recommendations.append("🟡 Improve error handling: Avoid information disclosure")
                elif test_name == 'tls_config':
                    recommendations.append("🟡 Strengthen TLS: Use TLS 1.2+ with strong ciphers")
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. {rec}")
        else:
            print("✅ No critical recommendations - maintain current security posture")
        
        print(f"\n{'='*70}\n")


# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MCP Server Security Validator - Tests SERVER security controls',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool tests THE SERVER's security controls by using multiple client
configurations to validate that the server properly enforces:

- Authentication (rejects invalid, accepts valid)
- HTTPS (rejects HTTP)
- POST-only methods (rejects GET)
- Rate limiting
- Security headers
- Proper error handling

Examples:
  python3 mcp_server_security_validator.py --server my_server
  python3 mcp_server_security_validator.py --all
  python3 mcp_server_security_validator.py --server my_server --verbose
        """
    )
    
    parser.add_argument('--config', default='mcp_clean.json', help='Path to config')
    parser.add_argument('--server', help='Server to test')
    parser.add_argument('--all', action='store_true', help='Test all servers')
    parser.add_argument('--list', action='store_true', help='List servers')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output-dir', default='reports', help='Output directory')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_mcp_config(args.config)
    
    # List servers
    if args.list:
        servers = list_available_servers(config)
        print(f"\n✅ Found {len(servers)} server(s):\n")
        for name in servers:
            print(f"  • {name}")
        return
    
    # Ensure output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Test server(s)
    if args.all:
        servers = list_available_servers(config)
        print(f"\n🛡️  Testing {len(servers)} MCP servers for security controls...\n")
        
        all_results = []
        for server_name in servers:
            server_config = get_server_config(config, server_name)
            validator = MCPServerSecurityValidator(server_name, server_config, args.verbose)
            results = validator.run_all_tests()
            all_results.append(results)
            
            # Save report
            output_file = os.path.join(args.output_dir, f"{server_name}_server_validation.json")
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\n📊 Report: {output_file}\n")
        
        # Combined report
        combined_file = os.path.join(args.output_dir, "all_servers_validation.json")
        with open(combined_file, 'w') as f:
            json.dump({
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'total_servers': len(servers),
                'results': all_results
            }, f, indent=2)
        
        print(f"\n📊 Combined report: {combined_file}")
        
    else:
        if not args.server:
            print("❌ Error: --server required (or use --all)")
            sys.exit(1)
        
        server_config = get_server_config(config, args.server)
        if not server_config:
            print(f"❌ Error: Server '{args.server}' not found")
            sys.exit(1)
        
        # Run validation
        validator = MCPServerSecurityValidator(args.server, server_config, args.verbose)
        results = validator.run_all_tests()
        
        # Save report
        output_file = os.path.join(args.output_dir, f"{args.server}_server_validation.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{'='*70}")
        print("FINAL SERVER SECURITY ASSESSMENT")
        print(f"{'='*70}")
        
        rating = results.get('security_rating', 'N/A')
        score = results.get('overall_security_score', 'N/A')
        
        rating_emoji = {
            'EXCELLENT': '🟢',
            'GOOD': '🟢',
            'FAIR': '🟡',
            'POOR': '🟠',
            'CRITICAL': '🔴'
        }.get(rating, '⚪')
        
        print(f"\n{rating_emoji} Server Security Rating: {rating}")
        print(f"📊 Security Score: {score}/100")
        print(f"\n📄 Report: {output_file}\n")


if __name__ == '__main__':
    main()

