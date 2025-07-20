#!/usr/bin/env python3
"""
Enterprise AI GitHub PR Reviewer - Advanced Features
Professional-grade code analysis with comprehensive metrics and security scoring.
"""

import os
import hmac
import hashlib
import json
import asyncio
import re
import csv
import io
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
from custom_rules import CustomRulesManager, integrate_custom_rules, create_rules_api_endpoints

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
import httpx
import logging
from openai import AsyncOpenAI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Code Review Platform", version="3.0.0")

# Configuration
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET") 
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not GITHUB_TOKEN:
    logger.warning("GITHUB_TOKEN not set - GitHub API calls will fail")

class Language(Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CPP = "cpp"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    UNKNOWN = "unknown"

class SecurityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class CodeIssue:
    line_number: int
    severity: str  # "critical", "high", "medium", "low"
    category: str  # "security", "performance", "style", "bug", "best_practice", "complexity"
    message: str
    suggestion: str
    rule_id: str
    confidence: float = 0.8  # AI confidence in the issue
    impact_score: int = 5  # Impact score 1-10

@dataclass
class SecurityMetrics:
    overall_score: int  # 0-100
    vulnerability_count: Dict[str, int]
    risk_level: str
    recommendations: List[str]

@dataclass
class PerformanceMetrics:
    complexity_score: int  # 0-100
    performance_issues: int
    optimization_suggestions: List[str]
    estimated_impact: str

@dataclass
class CodeQualityMetrics:
    maintainability_score: int  # 0-100
    readability_score: int  # 0-100
    test_coverage_estimate: int  # 0-100
    documentation_score: int  # 0-100

@dataclass
class ReviewData:
    pr_number: int
    repo_name: str
    overall_score: int
    total_issues: int
    issues_by_severity: Dict[str, int]
    issues_by_category: Dict[str, int]
    languages_detected: List[str]
    review_time: datetime
    ai_model: str
    security_metrics: SecurityMetrics
    performance_metrics: PerformanceMetrics
    quality_metrics: CodeQualityMetrics
    review_duration: float  # seconds
    lines_analyzed: int
    files_analyzed: int

class LanguageConfig:
    """Enhanced configuration for each programming language"""
    
    @staticmethod
    def get_config(language: Language) -> Dict:
        configs = {
            Language.PYTHON: {
                "extensions": [".py"],
                "comment_style": "#",
                "complexity_patterns": [
                    (r'if\s+.*\sand\s+.*\sand\s+', 3),  # Complex conditionals
                    (r'for\s+.*\sin\s+.*for\s+', 2),    # Nested loops
                    (r'try\s*:.*except.*except', 2),      # Multiple exception handling
                ],
                "security_patterns": [
                    (r'password\s*=\s*["\'][^"\']+["\']', "critical", "Hardcoded password detected"),
                    (r'api_key\s*=\s*["\'][^"\']+["\']', "critical", "Hardcoded API key detected"),
                    (r'eval\s*\(', "high", "Use of eval() is dangerous - code injection risk"),
                    (r'exec\s*\(', "high", "Use of exec() is dangerous - code execution risk"),
                    (r'pickle\.loads?\s*\(', "high", "Pickle deserialization vulnerability"),
                    (r'subprocess\.call.*shell\s*=\s*True', "high", "Shell injection vulnerability"),
                    (r'sql.*\+.*\+', "medium", "Potential SQL injection - use parameterized queries"),
                ],
                "performance_patterns": [
                    (r'\.append\s*\([^)]+\)\s*in\s+.*for', "medium", "Consider list comprehension for better performance"),
                    (r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(', "low", "Use enumerate() instead of range(len())"),
                    (r'.*\+\+', "low", "Use += operator instead"),
                    (r'open\s*\([^)]*\)(?!\s*with)', "medium", "Use context manager (with statement) for file operations"),
                ],
                "style_patterns": [
                    (r'def\s+[a-z]+[A-Z]', "low", "Use snake_case for function names (PEP 8)"),
                    (r'class\s+[a-z]', "medium", "Use PascalCase for class names (PEP 8)"),
                    (r'import\s+\*', "medium", "Avoid wildcard imports"),
                    (r'lambda.*lambda', "medium", "Avoid nested lambda functions"),
                ]
            },
            Language.JAVASCRIPT: {
                "extensions": [".js", ".jsx"],
                "comment_style": "//",
                "complexity_patterns": [
                    (r'if\s*\([^)]*&&[^)]*&&[^)]*\)', 2),
                    (r'function.*function', 2),
                    (r'\.then\s*\(.*\.then\s*\(', 2),
                ],
                "security_patterns": [
                    (r'eval\s*\(', "critical", "Use of eval() is dangerous - code injection risk"),
                    (r'innerHTML\s*=.*\+', "high", "Potential XSS vulnerability - use textContent or sanitization"),
                    (r'document\.write\s*\(', "high", "document.write() can cause XSS vulnerabilities"),
                    (r'localStorage\.setItem.*password', "medium", "Don't store passwords in localStorage"),
                    (r'setTimeout\s*\(\s*["\']', "medium", "Avoid string-based setTimeout - use functions"),
                ],
                "performance_patterns": [
                    (r'document\.getElementById.*loop', "medium", "Cache DOM queries outside loops"),
                    (r'.*\.forEach.*\.forEach', "medium", "Nested forEach can be inefficient"),
                    (r'new\s+Date\s*\(\s*\)\s*.*loop', "low", "Avoid creating dates in loops"),
                    (r'\$\(.*\)\s*\..*\$\(.*\)', "low", "Cache jQuery selectors"),
                ],
                "style_patterns": [
                    (r'var\s+', "medium", "Use let or const instead of var (ES6+)"),
                    (r'function\s+[A-Z]', "low", "Use camelCase for function names"),
                    (r'==\s*(?!==)', "medium", "Use strict equality (===) instead of =="),
                    (r'console\.log', "low", "Remove console.log statements before production"),
                ]
            },
            Language.JAVA: {
                "extensions": [".java"],
                "comment_style": "//",
                "complexity_patterns": [
                    (r'if\s*\([^)]*&&[^)]*&&[^)]*\)', 2),
                    (r'catch\s*\([^)]*\)\s*\{[^}]*\}\s*catch', 2),
                    (r'synchronized\s*\([^)]*\)\s*\{.*synchronized', 3),
                ],
                "security_patterns": [
                    (r'Runtime\.getRuntime\(\)\.exec', "critical", "Command injection risk - validate input thoroughly"),
                    (r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "high", "MD5 is cryptographically broken - use SHA-256+"),
                    (r'Random\s*\(\s*\)', "medium", "Use SecureRandom for security-sensitive operations"),
                    (r'Class\.forName\s*\(', "medium", "Dynamic class loading - validate class names"),
                    (r'PreparedStatement.*\+', "high", "Potential SQL injection - use parameterized queries only"),
                ],
                "performance_patterns": [
                    (r'String\s+\w+\s*=\s*"";\s*.*\+=', "medium", "Use StringBuilder for string concatenation"),
                    (r'new\s+.*Exception.*loop', "high", "Don't create exceptions in loops - major performance impact"),
                    (r'synchronized\s+.*\(\s*\)\s*\{', "medium", "Consider using concurrent collections instead"),
                ],
                "style_patterns": [
                    (r'public\s+class\s+[a-z]', "medium", "Class names should start with uppercase"),
                    (r'public\s+\w+\s+[A-Z].*\s*\(', "low", "Method names should start with lowercase"),
                    (r'if\s*\([^)]*\)\s*\{[^}]*\}\s*else\s*\{[^}]*\}', "info", "Consider ternary operator for simple if-else"),
                ]
            }
        }
        return configs.get(language, {
            "extensions": [],
            "comment_style": "//",
            "complexity_patterns": [],
            "security_patterns": [],
            "performance_patterns": [],
            "style_patterns": []
        })

class GitHubClient:
    """Enhanced GitHub API client with rate limiting and caching"""
    
    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Code-Review-Platform/3.0"
        }
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = datetime.now()
    
    async def check_rate_limit(self):
        """Check GitHub API rate limit"""
        if self.rate_limit_remaining <= 100:
            wait_time = (self.rate_limit_reset - datetime.now()).total_seconds()
            if wait_time > 0:
                logger.warning(f"Rate limit low, waiting {wait_time} seconds")
                await asyncio.sleep(min(wait_time, 60))
    
    async def get_pr_details(self, repo_full_name: str, pr_number: int) -> Dict:
        """Get complete PR details with metadata"""
        await self.check_rate_limit()
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            self._update_rate_limit(response.headers)
            response.raise_for_status()
            return response.json()
    
    async def get_pr_diff(self, repo_full_name: str, pr_number: int) -> str:
        """Fetch the diff for a pull request"""
        await self.check_rate_limit()
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}"
        
        async with httpx.AsyncClient() as client:
            headers = {**self.headers, "Accept": "application/vnd.github.v3.diff"}
            response = await client.get(url, headers=headers)
            self._update_rate_limit(response.headers)
            response.raise_for_status()
            return response.text
    
    async def get_pr_files(self, repo_full_name: str, pr_number: int) -> List[Dict]:
        """Get detailed list of changed files in the PR"""
        await self.check_rate_limit()
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}/files"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            self._update_rate_limit(response.headers)
            response.raise_for_status()
            return response.json()
    
    async def post_review_comment(self, repo_full_name: str, pr_number: int, 
                                commit_id: str, path: str, line: int, body: str) -> Dict:
        """Post a line-specific review comment with retry logic"""
        await self.check_rate_limit()
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}/comments"
        data = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=self.headers, json=data)
            self._update_rate_limit(response.headers)
            
            if response.status_code == 422:
                logger.warning(f"Could not post line comment at {path}:{line}, posting as general comment")
                return await self.post_pr_comment(repo_full_name, pr_number, f"**{path}:{line}** - {body}")
            
            response.raise_for_status()
            return response.json()
    
    async def post_pr_comment(self, repo_full_name: str, pr_number: int, body: str) -> Dict:
        """Post a general comment on the PR"""
        await self.check_rate_limit()
        url = f"{self.base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"
        data = {"body": body}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=self.headers, json=data)
            self._update_rate_limit(response.headers)
            response.raise_for_status()
            return response.json()
    
    async def submit_review(self, repo_full_name: str, pr_number: int, 
                          commit_id: str, event: str, body: str) -> Dict:
        """Submit a complete review with enhanced status"""
        await self.check_rate_limit()
        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}/reviews"
        data = {
            "commit_id": commit_id,
            "body": body,
            "event": event
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=self.headers, json=data)
            self._update_rate_limit(response.headers)
            response.raise_for_status()
            return response.json()
    
    def _update_rate_limit(self, headers: Dict):
        """Update rate limit tracking from response headers"""
        if 'x-ratelimit-remaining' in headers:
            self.rate_limit_remaining = int(headers['x-ratelimit-remaining'])
        if 'x-ratelimit-reset' in headers:
            self.rate_limit_reset = datetime.fromtimestamp(int(headers['x-ratelimit-reset']))

class EnhancedAIReviewer:
    """Advanced AI reviewer with comprehensive analysis capabilities"""
    
    def __init__(self, api_key: str):
        self.client = AsyncOpenAI(api_key=api_key) if api_key else None
        self.model = "gpt-4-turbo-preview"
    
    def detect_language(self, file_path: str) -> Language:
        """Enhanced language detection with confidence scoring"""
        extension_map = {
            '.py': Language.PYTHON,
            '.js': Language.JAVASCRIPT,
            '.jsx': Language.JAVASCRIPT,
            '.ts': Language.TYPESCRIPT,
            '.tsx': Language.TYPESCRIPT,
            '.java': Language.JAVA,
            '.cpp': Language.CPP,
            '.cc': Language.CPP,
            '.cxx': Language.CPP,
            '.c': Language.CPP,
            '.cs': Language.CSHARP,
            '.go': Language.GO,
            '.rs': Language.RUST,
            '.php': Language.PHP,
            '.rb': Language.RUBY,
            '.swift': Language.SWIFT,
            '.kt': Language.KOTLIN,
        }
        
        for ext, lang in extension_map.items():
            if file_path.lower().endswith(ext):
                return lang
        
        return Language.UNKNOWN
    
    def parse_diff_lines(self, diff_content: str) -> Dict[str, List[Tuple[int, str]]]:
        """Enhanced diff parsing with better line tracking"""
        files = {}
        current_file = None
        current_line_num = 0
        
        lines = diff_content.split('\n')
        
        for line in lines:
            if line.startswith('+++'):
                current_file = line[6:] if line.startswith('+++ b/') else line[4:]
                if current_file != '/dev/null':  # Skip deleted files
                    files[current_file] = []
                current_line_num = 0
            elif line.startswith('@@'):
                match = re.search(r'\+(\d+)', line)
                if match:
                    current_line_num = int(match.group(1)) - 1
            elif line.startswith('+') and not line.startswith('+++'):
                if current_file and current_file in files:
                    current_line_num += 1
                    files[current_file].append((current_line_num, line[1:]))
            elif not line.startswith('-'):
                current_line_num += 1
        
        return files
    
    async def analyze_file_diff(self, file_path: str, diff_lines: List[Tuple[int, str]], 
                              language: Language) -> Tuple[List[CodeIssue], SecurityMetrics, PerformanceMetrics, CodeQualityMetrics]:
        """Comprehensive file analysis with advanced metrics"""
        if not diff_lines:
            return [], self._default_security_metrics(), self._default_performance_metrics(), self._default_quality_metrics()
        
        start_time = datetime.now()
        
        # Get language-specific configuration
        lang_config = LanguageConfig.get_config(language)
        
        # Pattern-based analysis
        issues = self._pattern_analysis(diff_lines, language, lang_config)
        
        # Calculate metrics
        security_metrics = self._calculate_security_metrics(issues, diff_lines)
        performance_metrics = self._calculate_performance_metrics(issues, diff_lines, lang_config)
        quality_metrics = self._calculate_quality_metrics(diff_lines, language)
        
        analysis_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Analyzed {file_path} in {analysis_time:.2f}s - found {len(issues)} issues")
        
        return issues, security_metrics, performance_metrics, quality_metrics
    
    def _pattern_analysis(self, diff_lines: List[Tuple[int, str]], 
                         language: Language, lang_config: Dict) -> List[CodeIssue]:
        """Enhanced pattern-based analysis with severity scoring"""
        issues = []
        
        for line_num, line_content in diff_lines:
            # Security analysis
            for pattern, severity, message in lang_config.get('security_patterns', []):
                if re.search(pattern, line_content, re.IGNORECASE):
                    impact_score = {"critical": 10, "high": 8, "medium": 5, "low": 3}.get(severity, 5)
                    issues.append(CodeIssue(
                        line_number=line_num,
                        severity=severity,
                        category="security",
                        message=message,
                        suggestion=self._generate_security_suggestion(pattern, message),
                        rule_id=f"security_{language.value}_{len(issues)}",
                        confidence=0.9,
                        impact_score=impact_score
                    ))
            
            # Performance analysis
            for pattern, severity, message in lang_config.get('performance_patterns', []):
                if re.search(pattern, line_content, re.IGNORECASE):
                    impact_score = {"high": 7, "medium": 5, "low": 3}.get(severity, 4)
                    issues.append(CodeIssue(
                        line_number=line_num,
                        severity=severity,
                        category="performance",
                        message=message,
                        suggestion=self._generate_performance_suggestion(pattern, message),
                        rule_id=f"performance_{language.value}_{len(issues)}",
                        confidence=0.8,
                        impact_score=impact_score
                    ))
            
            # Style analysis
            for pattern, severity, message in lang_config.get('style_patterns', []):
                if re.search(pattern, line_content, re.IGNORECASE):
                    impact_score = {"medium": 4, "low": 2, "info": 1}.get(severity, 2)
                    issues.append(CodeIssue(
                        line_number=line_num,
                        severity=severity,
                        category="style",
                        message=message,
                        suggestion=self._generate_style_suggestion(pattern, message),
                        rule_id=f"style_{language.value}_{len(issues)}",
                        confidence=0.7,
                        impact_score=impact_score
                    ))
            
            # Complexity analysis
            for pattern, complexity_score in lang_config.get('complexity_patterns', []):
                if re.search(pattern, line_content, re.IGNORECASE):
                    severity = "high" if complexity_score >= 3 else "medium"
                    issues.append(CodeIssue(
                        line_number=line_num,
                        severity=severity,
                        category="complexity",
                        message=f"High complexity detected (score: {complexity_score})",
                        suggestion="Consider refactoring to reduce complexity",
                        rule_id=f"complexity_{language.value}_{len(issues)}",
                        confidence=0.8,
                        impact_score=complexity_score + 2
                    ))
        
        return issues
    
    def _calculate_security_metrics(self, issues: List[CodeIssue], diff_lines: List[Tuple[int, str]]) -> SecurityMetrics:
        """Calculate comprehensive security metrics"""
        security_issues = [issue for issue in issues if issue.category == "security"]
        
        # Count vulnerabilities by type
        vulnerability_count = {
            "injection": 0,
            "authentication": 0,
            "encryption": 0,
            "configuration": 0,
            "other": 0
        }
        
        for issue in security_issues:
            if any(keyword in issue.message.lower() for keyword in ['injection', 'sql', 'xss']):
                vulnerability_count["injection"] += 1
            elif any(keyword in issue.message.lower() for keyword in ['password', 'auth', 'token']):
                vulnerability_count["authentication"] += 1
            elif any(keyword in issue.message.lower() for keyword in ['encrypt', 'hash', 'crypto']):
                vulnerability_count["encryption"] += 1
            elif any(keyword in issue.message.lower() for keyword in ['config', 'setting']):
                vulnerability_count["configuration"] += 1
            else:
                vulnerability_count["other"] += 1
        
        # Calculate overall security score
        critical_issues = len([i for i in security_issues if i.severity == "critical"])
        high_issues = len([i for i in security_issues if i.severity == "high"])
        medium_issues = len([i for i in security_issues if i.severity == "medium"])
        
        # Score calculation (100 - penalties)
        score = 100
        score -= critical_issues * 25  # Critical issues have major impact
        score -= high_issues * 15
        score -= medium_issues * 8
        score = max(score, 0)
        
        # Determine risk level
        if critical_issues > 0 or high_issues >= 3:
            risk_level = "HIGH"
        elif high_issues > 0 or medium_issues >= 5:
            risk_level = "MEDIUM"
        elif medium_issues > 0:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        # Generate recommendations
        recommendations = []
        if critical_issues > 0:
            recommendations.append("Immediate action required: Fix critical security vulnerabilities")
        if vulnerability_count["injection"] > 0:
            recommendations.append("Implement input validation and parameterized queries")
        if vulnerability_count["authentication"] > 0:
            recommendations.append("Review authentication and authorization mechanisms")
        if vulnerability_count["encryption"] > 0:
            recommendations.append("Use strong encryption algorithms and secure key management")
        
        return SecurityMetrics(
            overall_score=score,
            vulnerability_count=vulnerability_count,
            risk_level=risk_level,
            recommendations=recommendations
        )
    
    def _calculate_performance_metrics(self, issues: List[CodeIssue], diff_lines: List[Tuple[int, str]], lang_config: Dict) -> PerformanceMetrics:
        """Calculate performance metrics and optimization suggestions"""
        performance_issues = [issue for issue in issues if issue.category == "performance"]
        complexity_issues = [issue for issue in issues if issue.category == "complexity"]
        
        # Calculate complexity score
        total_complexity = sum(issue.impact_score for issue in complexity_issues)
        line_count = len(diff_lines)
        
        if line_count > 0:
            complexity_per_line = total_complexity / line_count
            complexity_score = max(100 - int(complexity_per_line * 20), 0)
        else:
            complexity_score = 100
        
        # Performance impact estimation
        high_impact_issues = len([i for i in performance_issues if i.severity == "high"])
        medium_impact_issues = len([i for i in performance_issues if i.severity == "medium"])
        
        if high_impact_issues > 0:
            estimated_impact = "HIGH - Significant performance degradation likely"
        elif medium_impact_issues >= 3:
            estimated_impact = "MEDIUM - Noticeable performance impact"
        elif len(performance_issues) > 0:
            estimated_impact = "LOW - Minor performance impact"
        else:
            estimated_impact = "MINIMAL - No significant performance concerns"
        
        # Generate optimization suggestions
        suggestions = []
        if any("loop" in issue.message.lower() for issue in performance_issues):
            suggestions.append("Optimize loop operations and reduce nested iterations")
        if any("database" in issue.message.lower() or "query" in issue.message.lower() for issue in performance_issues):
            suggestions.append("Implement database query optimization and caching")
        if any("memory" in issue.message.lower() for issue in performance_issues):
            suggestions.append("Review memory usage patterns and implement efficient data structures")
        if complexity_score < 70:
            suggestions.append("Reduce code complexity through refactoring and modularization")
        
        return PerformanceMetrics(
            complexity_score=complexity_score,
            performance_issues=len(performance_issues),
            optimization_suggestions=suggestions,
            estimated_impact=estimated_impact
        )
    
    def _calculate_quality_metrics(self, diff_lines: List[Tuple[int, str]], language: Language) -> CodeQualityMetrics:
        """Calculate code quality metrics"""
        if not diff_lines:
            return self._default_quality_metrics()
        
        total_lines = len(diff_lines)
        
        # Maintainability score (based on line length, complexity, comments)
        long_lines = sum(1 for _, line in diff_lines if len(line) > 100)
        comment_lines = sum(1 for _, line in diff_lines if line.strip().startswith('#') or line.strip().startswith('//'))
        
        maintainability = 100 - (long_lines * 5) + (comment_lines * 2)
        maintainability = max(min(maintainability, 100), 0)
        
        # Readability score (based on naming, structure)
        readable_names = sum(1 for _, line in diff_lines if re.search(r'[a-z_][a-z0-9_]*', line))
        readability = min((readable_names / total_lines) * 100, 100) if total_lines > 0 else 100
        
        # Test coverage estimate (based on test-related patterns)
        test_indicators = sum(1 for _, line in diff_lines if any(keyword in line.lower() for keyword in ['test', 'assert', 'expect', 'mock']))
        test_coverage = min((test_indicators / max(total_lines * 0.3, 1)) * 100, 100)
        
        # Documentation score (based on comments and docstrings)
        doc_indicators = sum(1 for _, line in diff_lines if any(keyword in line for keyword in ['"""', "'''", '//', '#']))
        documentation = min((doc_indicators / max(total_lines * 0.2, 1)) * 100, 100)
        
        return CodeQualityMetrics(
            maintainability_score=int(maintainability),
            readability_score=int(readability),
            test_coverage_estimate=int(test_coverage),
            documentation_score=int(documentation)
        )
    
    def _default_security_metrics(self) -> SecurityMetrics:
        return SecurityMetrics(
            overall_score=100,
            vulnerability_count={"injection": 0, "authentication": 0, "encryption": 0, "configuration": 0, "other": 0},
            risk_level="MINIMAL",
            recommendations=[]
        )
    
    def _default_performance_metrics(self) -> PerformanceMetrics:
        return PerformanceMetrics(
            complexity_score=100,
            performance_issues=0,
            optimization_suggestions=[],
            estimated_impact="MINIMAL"
        )
    
    def _default_quality_metrics(self) -> CodeQualityMetrics:
        return CodeQualityMetrics(
            maintainability_score=100,
            readability_score=100,
            test_coverage_estimate=0,
            documentation_score=0
        )
    
    def _generate_security_suggestion(self, pattern: str, message: str) -> str:
        """Generate contextual security suggestions"""
        suggestions = {
            "password": "Use environment variables or secure configuration management",
            "eval": "Use safe alternatives like ast.literal_eval() or JSON parsing",
            "sql": "Use parameterized queries or ORM methods",
            "xss": "Use proper output encoding and Content Security Policy",
            "injection": "Implement input validation and sanitization"
        }
        
        for keyword, suggestion in suggestions.items():
            if keyword in message.lower():
                return suggestion
        
        return "Review and implement secure coding practices"
    
    def _generate_performance_suggestion(self, pattern: str, message: str) -> str:
        """Generate contextual performance suggestions"""
        suggestions = {
            "loop": "Consider list comprehensions or vectorized operations",
            "append": "Use list comprehensions or pre-allocate lists when possible",
            "enumerate": "Use enumerate() for better performance and readability",
            "dom": "Cache DOM queries and use document fragments for multiple operations"
        }
        
        for keyword, suggestion in suggestions.items():
            if keyword in message.lower():
                return suggestion
        
        return "Optimize for better performance and resource usage"
    
    def _generate_style_suggestion(self, pattern: str, message: str) -> str:
        """Generate contextual style suggestions"""
        suggestions = {
            "snake_case": "Follow language naming conventions",
            "camelcase": "Use appropriate case convention for the language",
            "var": "Use modern variable declarations (let/const)",
            "equality": "Use strict equality operators"
        }
        
        for keyword, suggestion in suggestions.items():
            if keyword in message.lower():
                return suggestion
        
        return "Follow language-specific style guidelines"

# Enhanced storage and connection management
review_storage = []
active_connections = []

class ConnectionManager:
    """Enhanced WebSocket connection manager with broadcasting capabilities"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_metadata = {}
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_metadata[websocket] = {
            "connected_at": datetime.now(),
            "messages_sent": 0
        }
        await self.broadcast({
            "type": "connection_update",
            "data": {"total_connections": len(self.active_connections)}
        })
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.connection_metadata:
            del self.connection_metadata[websocket]
    
    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
                self.connection_metadata[connection]["messages_sent"] += 1
            except:
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

# Initialize clients
github_client = GitHubClient(GITHUB_TOKEN) if GITHUB_TOKEN else None
ai_reviewer = EnhancedAIReviewer(OPENAI_API_KEY) if OPENAI_API_KEY else None

rules_manager = None
if ai_reviewer:
    try:
        from custom_rules import CustomRulesManager, integrate_custom_rules, create_rules_api_endpoints
        rules_manager = integrate_custom_rules(ai_reviewer)
        create_rules_api_endpoints(app, rules_manager)
        logger.info("✅ Custom rules system initialized")
    except ImportError:
        logger.warning("⚠️ Custom rules module not found - continuing without custom rules")
    except Exception as e:
        logger.error(f"❌ Failed to initialize custom rules: {e}")

def verify_github_signature(payload_body: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature"""
    if not GITHUB_WEBHOOK_SECRET:
        logger.warning("No webhook secret configured - skipping signature verification")
        return True
    
    expected_signature = "sha256=" + hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload_body,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)

async def process_pull_request(pr_data: Dict, action: str):
    """Enhanced PR processing with comprehensive analysis"""
    if not github_client or not ai_reviewer:
        logger.error("GitHub client or AI reviewer not initialized")
        return
    
    start_time = datetime.now()
    repo_full_name = pr_data["base"]["repo"]["full_name"]
    pr_number = pr_data["number"]
    commit_sha = pr_data["head"]["sha"]
    pr_title = pr_data.get("title", "")
    
    logger.info(f"Processing PR #{pr_number} in {repo_full_name} (action: {action})")
    
    # Broadcast start notification
    await manager.broadcast({
        "type": "review_started",
        "data": {
            "pr_number": pr_number,
            "repo": repo_full_name,
            "title": pr_title,
            "status": "analyzing",
            "timestamp": start_time.isoformat()
        }
    })
    
    try:
        # Get PR diff and parse it
        diff = await github_client.get_pr_diff(repo_full_name, pr_number)
        file_changes = ai_reviewer.parse_diff_lines(diff)
        
        all_issues = []
        languages_detected = set()
        total_lines_analyzed = 0
        files_analyzed = 0
        
        # Aggregate metrics
        all_security_metrics = []
        all_performance_metrics = []
        all_quality_metrics = []
        
        # Analyze each changed file
        for file_path, diff_lines in file_changes.items():
            if not diff_lines:
                continue
                
            language = ai_reviewer.detect_language(file_path)
            languages_detected.add(language.value)
            total_lines_analyzed += len(diff_lines)
            files_analyzed += 1
            
            # Comprehensive analysis
            file_issues, security_metrics, performance_metrics, quality_metrics = await ai_reviewer.analyze_file_diff(
                file_path, diff_lines, language
            )
            
            all_security_metrics.append(security_metrics)
            all_performance_metrics.append(performance_metrics)
            all_quality_metrics.append(quality_metrics)
            
            # Post enhanced line-specific comments
            for issue in file_issues:
                severity_emoji = {
                    "critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢", "info": "ℹ️"
                }.get(issue.severity, "ℹ️")
                
                category_emoji = {
                    "security": "🔒", "performance": "⚡", "style": "🎨",
                    "bug": "🐛", "best_practice": "✅", "complexity": "🧠"
                }.get(issue.category, "💡")
                
                comment_body = f"""{severity_emoji} {category_emoji} **{issue.category.title()} Issue** (Impact: {issue.impact_score}/10)

{issue.message}

💡 **Suggestion:** {issue.suggestion}

📊 **Confidence:** {int(issue.confidence * 100)}% | **Rule:** {issue.rule_id}"""
                
                try:
                    await github_client.post_review_comment(
                        repo_full_name, pr_number, commit_sha,
                        file_path, issue.line_number, comment_body
                    )
                except Exception as e:
                    logger.warning(f"Failed to post line comment: {e}")
            
            all_issues.extend(file_issues)
        
        # Calculate aggregate metrics
        issues_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        issues_by_category = {"security": 0, "performance": 0, "style": 0, "bug": 0, "best_practice": 0, "complexity": 0}
        
        for issue in all_issues:
            issues_by_severity[issue.severity] += 1
            issues_by_category[issue.category] += 1
        
        # Aggregate security metrics
        overall_security = SecurityMetrics(
            overall_score=int(statistics.mean([sm.overall_score for sm in all_security_metrics])) if all_security_metrics else 100,
            vulnerability_count={"injection": 0, "authentication": 0, "encryption": 0, "configuration": 0, "other": 0},
            risk_level="MINIMAL",
            recommendations=[]
        )
        
        # Aggregate performance metrics
        overall_performance = PerformanceMetrics(
            complexity_score=int(statistics.mean([pm.complexity_score for pm in all_performance_metrics])) if all_performance_metrics else 100,
            performance_issues=sum(pm.performance_issues for pm in all_performance_metrics),
            optimization_suggestions=[],
            estimated_impact="MINIMAL"
        )
        
        # Aggregate quality metrics
        overall_quality = CodeQualityMetrics(
            maintainability_score=int(statistics.mean([qm.maintainability_score for qm in all_quality_metrics])) if all_quality_metrics else 100,
            readability_score=int(statistics.mean([qm.readability_score for qm in all_quality_metrics])) if all_quality_metrics else 100,
            test_coverage_estimate=int(statistics.mean([qm.test_coverage_estimate for qm in all_quality_metrics])) if all_quality_metrics else 0,
            documentation_score=int(statistics.mean([qm.documentation_score for qm in all_quality_metrics])) if all_quality_metrics else 0
        )
        
        # Calculate overall score
        total_issues = len(all_issues)
        critical_issues = issues_by_severity["critical"]
        high_issues = issues_by_severity["high"]
        
        base_score = 100
        score_penalty = (critical_issues * 20) + (high_issues * 12) + (issues_by_severity["medium"] * 6) + (issues_by_severity["low"] * 2)
        overall_score = max(base_score - score_penalty, 0)
        
        # Determine review status
        if critical_issues >= 1:
            review_event = "REQUEST_CHANGES"
            status_emoji = "🚨"
        elif critical_issues + high_issues >= 3:
            review_event = "REQUEST_CHANGES"
            status_emoji = "🔴"
        elif high_issues >= 1 or issues_by_severity["medium"] >= 8:
            review_event = "COMMENT"
            status_emoji = "🟡"
        else:
            review_event = "APPROVE"
            status_emoji = "✅"
        
        # Enhanced summary
        review_duration = (datetime.now() - start_time).total_seconds()
        
        summary_body = f"""## {status_emoji} AI Code Review Analysis

### 📊 **Overall Assessment**
**Score:** {overall_score}/100 | **Security:** {overall_security.overall_score}/100 | **Performance:** {overall_performance.complexity_score}/100

### 🔍 **Analysis Summary**
- **Files Analyzed:** {files_analyzed}
- **Lines Reviewed:** {total_lines_analyzed}
- **Languages:** {', '.join(sorted(languages_detected))}
- **Review Duration:** {review_duration:.2f}s

### 📈 **Issue Breakdown**
- 🚨 **Critical:** {issues_by_severity['critical']} issues
- 🔴 **High:** {issues_by_severity['high']} issues  
- 🟡 **Medium:** {issues_by_severity['medium']} issues
- 🟢 **Low:** {issues_by_severity['low']} issues

### 🏷️ **By Category**
"""
        
        for category, count in issues_by_category.items():
            if count > 0:
                category_emoji = {
                    "security": "🔒", "performance": "⚡", "style": "🎨",
                    "bug": "🐛", "best_practice": "✅", "complexity": "🧠"
                }.get(category, "💡")
                summary_body += f"- {category_emoji} **{category.title()}:** {count} issue(s)\n"
        
        if total_issues == 0:
            summary_body += "\n🎉 **Excellent work!** No issues found in this analysis."
        
        summary_body += f"""

### 🛡️ **Security Assessment**
**Risk Level:** {overall_security.risk_level} | **Score:** {overall_security.overall_score}/100

### ⚡ **Performance Assessment**  
**Complexity Score:** {overall_performance.complexity_score}/100 | **Impact:** {overall_performance.estimated_impact}

### 📋 **Code Quality**
- **Maintainability:** {overall_quality.maintainability_score}/100
- **Readability:** {overall_quality.readability_score}/100
- **Documentation:** {overall_quality.documentation_score}/100

---
🤖 **AI Platform:** Enterprise Code Review v3.0  
⏱️ **Analyzed:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC  
💬 **Individual feedback posted on specific lines above**"""
        
        # Submit the comprehensive review
        await github_client.submit_review(
            repo_full_name, pr_number, commit_sha, review_event, summary_body
        )
        
        # Store enhanced review data
        review_data = ReviewData(
            pr_number=pr_number,
            repo_name=repo_full_name,
            overall_score=overall_score,
            total_issues=total_issues,
            issues_by_severity=issues_by_severity,
            issues_by_category=issues_by_category,
            languages_detected=list(languages_detected),
            review_time=datetime.now(),
            ai_model="enhanced-pattern-analysis",
            security_metrics=overall_security,
            performance_metrics=overall_performance,
            quality_metrics=overall_quality,
            review_duration=review_duration,
            lines_analyzed=total_lines_analyzed,
            files_analyzed=files_analyzed
        )
        review_storage.append(review_data)
        
        # Broadcast completion
        await manager.broadcast({
            "type": "review_completed",
            "data": {
                "pr_number": pr_number,
                "repo": repo_full_name,
                "score": overall_score,
                "total_issues": total_issues,
                "issues_by_severity": issues_by_severity,
                "languages": list(languages_detected),
                "security_score": overall_security.overall_score,
                "performance_score": overall_performance.complexity_score,
                "status": "completed",
                "timestamp": datetime.now().isoformat()
            }
        })
        
        logger.info(f"Enhanced review completed for PR #{pr_number} - Score: {overall_score}/100, Issues: {total_issues}, Duration: {review_duration:.2f}s")
        
    except Exception as e:
        logger.error(f"Error processing PR #{pr_number}: {str(e)}")
        await manager.broadcast({
            "type": "review_error",
            "data": {
                "pr_number": pr_number,
                "repo": repo_full_name,
                "error": str(e),
                "status": "error",
                "timestamp": datetime.now().isoformat()
            }
        })

# Mount static files
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/")
async def root():
    """Enhanced service information"""
    return {
        "status": "healthy",
        "service": "AI Code Review Platform",
        "version": "3.0.0",
        "features": [
            "smart_line_comments",
            "multi_language_analysis", 
            "security_scoring",
            "performance_metrics",
            "code_quality_assessment",
            "real_time_dashboard",
            "advanced_analytics",
            "export_functionality"
        ],
        "github_configured": GITHUB_TOKEN is not None,
        "ai_configured": OPENAI_API_KEY is not None,
        "active_connections": len(manager.active_connections),
        "total_reviews": len(review_storage)
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the enhanced dashboard"""
    try:
        import os
        if os.path.exists("dashboard.html"):
            with open("dashboard.html", "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        else:
            return HTMLResponse(content="""
            <html><body style="font-family: Arial, sans-serif; padding: 20px; background: #0f0f23; color: white;">
            <h1>❌ Dashboard Not Found</h1>
            <p>The dashboard.html file is missing. Please copy the Professional Dashboard HTML content.</p>
            <p><strong>Current directory:</strong> """ + os.getcwd() + """</p>
            <p><strong>Files found:</strong> """ + ", ".join(os.listdir(".")) + """</p>
            <p><a href="/" style="color: #3b82f6;">← Back to API</a></p>
            </body></html>
            """, status_code=404)
    except Exception as e:
        return HTMLResponse(content=f"""
        <html><body style="font-family: Arial, sans-serif; padding: 20px; background: #0f0f23; color: white;">
        <h1>❌ Dashboard Error</h1>
        <p>Error loading dashboard: {str(e)}</p>
        <p><a href="/" style="color: #3b82f6;">← Back to API</a></p>
        </body></html>
        """, status_code=500)

@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Enhanced webhook handler with improved logging"""
    
    payload_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    event_type = request.headers.get("X-GitHub-Event", "")
    
    if not verify_github_signature(payload_body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    try:
        payload = json.loads(payload_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    logger.info(f"Received GitHub event: {event_type}")
    
    if event_type == "pull_request":
        action = payload.get("action")
        pr_data = payload.get("pull_request")
        
        if action in ["opened", "synchronize", "reopened"]:
            background_tasks.add_task(process_pull_request, pr_data, action)
        
        return {"status": "received", "action": action, "timestamp": datetime.now().isoformat()}
    
    elif event_type == "ping":
        return {"status": "pong", "zen": payload.get("zen"), "timestamp": datetime.now().isoformat()}
    
    return {"status": "ignored", "event": event_type, "timestamp": datetime.now().isoformat()}

# Enhanced API endpoints
@app.get("/api/reviews")
async def get_reviews(limit: int = 50, offset: int = 0):
    """Get paginated reviews with enhanced data"""
    sorted_reviews = sorted(review_storage, key=lambda x: x.review_time, reverse=True)
    paginated_reviews = sorted_reviews[offset:offset + limit]
    
    return {
        "reviews": [
            {
                "pr_number": r.pr_number,
                "repo_name": r.repo_name,
                "overall_score": r.overall_score,
                "total_issues": r.total_issues,
                "issues_by_severity": r.issues_by_severity,
                "issues_by_category": r.issues_by_category,
                "languages_detected": r.languages_detected,
                "review_time": r.review_time.isoformat(),
                "ai_model": r.ai_model,
                "security_score": r.security_metrics.overall_score,
                "performance_score": r.performance_metrics.complexity_score,
                "quality_score": r.quality_metrics.maintainability_score,
                "review_duration": r.review_duration,
                "lines_analyzed": r.lines_analyzed,
                "files_analyzed": r.files_analyzed
            }
            for r in paginated_reviews
        ],
        "total": len(review_storage),
        "offset": offset,
        "limit": limit
    }

@app.get("/api/stats")
async def get_enhanced_stats():
    """Get comprehensive statistics"""
    if not review_storage:
        return {
            "total_reviews": 0,
            "avg_score": 0,
            "total_issues": 0,
            "avg_security_score": 0,
            "avg_performance_score": 0,
            "language_distribution": {},
            "issue_trends": [],
            "security_trends": []
        }
    
    total_reviews = len(review_storage)
    avg_score = statistics.mean(r.overall_score for r in review_storage)
    total_issues = sum(r.total_issues for r in review_storage)
    avg_security_score = statistics.mean(r.security_metrics.overall_score for r in review_storage)
    avg_performance_score = statistics.mean(r.performance_metrics.complexity_score for r in review_storage)
    
    # Language distribution
    lang_counts = {}
    for review in review_storage:
        for lang in review.languages_detected:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
    
    # Issue trends (last 7 days)
    now = datetime.now()
    issue_trends = []
    for i in range(7):
        date = now - timedelta(days=i)
        day_reviews = [r for r in review_storage if r.review_time.date() == date.date()]
        total_day_issues = sum(r.total_issues for r in day_reviews)
        issue_trends.append({
            "date": date.strftime("%Y-%m-%d"),
            "issues": total_day_issues,
            "reviews": len(day_reviews)
        })
    
    # Security trends
    security_trends = []
    for i in range(7):
        date = now - timedelta(days=i)
        day_reviews = [r for r in review_storage if r.review_time.date() == date.date()]
        avg_security = statistics.mean([r.security_metrics.overall_score for r in day_reviews]) if day_reviews else 100
        security_trends.append({
            "date": date.strftime("%Y-%m-%d"),
            "security_score": int(avg_security)
        })
    
    return {
        "total_reviews": total_reviews,
        "avg_score": round(avg_score, 1),
        "total_issues": total_issues,
        "avg_security_score": round(avg_security_score, 1),
        "avg_performance_score": round(avg_performance_score, 1),
        "language_distribution": lang_counts,
        "issue_trends": list(reversed(issue_trends)),
        "security_trends": list(reversed(security_trends))
    }

@app.get("/api/export/reviews")
async def export_reviews(format: str = "csv"):
    """Export reviews in various formats"""
    if not review_storage:
        raise HTTPException(status_code=404, detail="No reviews to export")
    
    if format.lower() == "csv":
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Headers
        writer.writerow([
            "PR Number", "Repository", "Overall Score", "Total Issues",
            "Critical Issues", "High Issues", "Medium Issues", "Low Issues",
            "Security Score", "Performance Score", "Quality Score",
            "Languages", "Review Time", "Duration (s)", "Lines Analyzed", "Files Analyzed"
        ])
        
        # Data rows
        for review in sorted(review_storage, key=lambda x: x.review_time, reverse=True):
            writer.writerow([
                review.pr_number,
                review.repo_name,
                review.overall_score,
                review.total_issues,
                review.issues_by_severity.get("critical", 0),
                review.issues_by_severity.get("high", 0),
                review.issues_by_severity.get("medium", 0),
                review.issues_by_severity.get("low", 0),
                review.security_metrics.overall_score,
                review.performance_metrics.complexity_score,
                review.quality_metrics.maintainability_score,
                ", ".join(review.languages_detected),
                review.review_time.isoformat(),
                round(review.review_duration, 2),
                review.lines_analyzed,
                review.files_analyzed
            ])
        
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=code_reviews_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
    
    elif format.lower() == "json":
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "total_reviews": len(review_storage),
            "reviews": [asdict(review) for review in review_storage]
        }
        
        return StreamingResponse(
            io.BytesIO(json.dumps(export_data, indent=2, default=str).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=code_reviews_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
        )
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'csv' or 'json'")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Enhanced WebSocket endpoint with connection tracking"""
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/health")
async def enhanced_health_check():
    """Comprehensive health check with system metrics"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "3.0.0",
        "components": {
            "github_token": "configured" if GITHUB_TOKEN else "missing",
            "openai_key": "configured" if OPENAI_API_KEY else "missing",
            "webhook_secret": "configured" if GITHUB_WEBHOOK_SECRET else "missing"
        },
        "features": {
            "smart_comments": True,
            "multi_language": True,
            "security_analysis": True,
            "performance_metrics": True,
            "quality_assessment": True,
            "real_time_dashboard": True,
            "advanced_analytics": True,
            "export_functionality": True
        },
        "supported_languages": [lang.value for lang in Language if lang != Language.UNKNOWN],
        "metrics": {
            "active_connections": len(manager.active_connections),
            "total_reviews": len(review_storage),
            "avg_review_score": round(statistics.mean([r.overall_score for r in review_storage]), 1) if review_storage else 0,
            "avg_security_score": round(statistics.mean([r.security_metrics.overall_score for r in review_storage]), 1) if review_storage else 0,
            "total_issues_found": sum(r.total_issues for r in review_storage),
            "uptime": "N/A"  # Could be calculated with startup time tracking
        },
        "api_endpoints": [
            "/", "/health", "/webhook", "/dashboard",
            "/api/reviews", "/api/stats", "/api/export/reviews",
            "/ws"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)