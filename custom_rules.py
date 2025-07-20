#!/usr/bin/env python3
"""
Custom Rules Configuration System for AI Code Review Platform
Allows teams to define their own coding standards and rules.
"""

import json
import yaml
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

@dataclass
class CodeIssue:
    line_number: int
    severity: str
    category: str
    message: str
    suggestion: str
    rule_id: str
    confidence: float
    impact_score: int

@dataclass
class CustomRule:
    id: str
    name: str
    description: str
    pattern: str
    severity: str  # "critical", "high", "medium", "low", "info"
    category: str  # "security", "performance", "style", "bug", "best_practice"
    message: str
    suggestion: str
    languages: List[str]  # Which languages this rule applies to
    enabled: bool = True
    confidence: float = 0.8

class CustomRulesManager:
    """Manages custom coding rules for organizations"""
    
    def __init__(self, config_path: str = "rules_config.yml"):
        self.config_path = config_path
        self.rules: Dict[str, CustomRule] = {}
        self.load_rules()
    
    def load_rules(self):
        """Load rules from configuration file"""
        try:
            if Path(self.config_path).exists():
                with open(self.config_path, 'r') as file:
                    config = yaml.safe_load(file)
                    
                    for rule_data in config.get('custom_rules', []):
                        rule = CustomRule(**rule_data)
                        self.rules[rule.id] = rule
                        
                print(f"Loaded {len(self.rules)} custom rules")
            else:
                # Create default configuration
                self.create_default_config()
        except Exception as e:
            print(f"Error loading rules: {e}")
            self.create_default_config()
    
    def create_default_config(self):
        """Create a default rules configuration file"""
        default_rules = [
            {
                "id": "no_hardcoded_secrets",
                "name": "No Hardcoded Secrets",
                "description": "Detect hardcoded passwords, API keys, and tokens",
                "pattern": r"(password|api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]",
                "severity": "critical",
                "category": "security",
                "message": "Hardcoded secret detected",
                "suggestion": "Use environment variables or secure configuration management",
                "languages": ["python", "javascript", "java", "csharp"],
                "enabled": True,
                "confidence": 0.9
            },
            {
                "id": "sql_injection_risk",
                "name": "SQL Injection Prevention",
                "description": "Detect potential SQL injection vulnerabilities",
                "pattern": r"(SELECT|INSERT|UPDATE|DELETE).*\+.*\+",
                "severity": "high",
                "category": "security",
                "message": "Potential SQL injection vulnerability",
                "suggestion": "Use parameterized queries or prepared statements",
                "languages": ["python", "java", "csharp", "php"],
                "enabled": True,
                "confidence": 0.8
            },
            {
                "id": "console_log_production",
                "name": "No Console Logs in Production",
                "description": "Detect console.log statements that should be removed",
                "pattern": r"console\.(log|debug|info)",
                "severity": "low",
                "category": "style",
                "message": "Console log statement found",
                "suggestion": "Remove console.log statements before production deployment",
                "languages": ["javascript", "typescript"],
                "enabled": True,
                "confidence": 0.9
            },
            {
                "id": "todo_comments",
                "name": "TODO Comments",
                "description": "Track TODO and FIXME comments",
                "pattern": r"(TODO|FIXME|HACK|XXX)",
                "severity": "info",
                "category": "best_practice",
                "message": "TODO comment found",
                "suggestion": "Consider creating a ticket or addressing the TODO item",
                "languages": ["python", "javascript", "java", "csharp", "go", "rust"],
                "enabled": True,
                "confidence": 0.7
            },
            {
                "id": "large_function",
                "name": "Function Size Limit",
                "description": "Detect functions that are too large",
                "pattern": r"def\s+\w+\([^)]*\):\s*(?:\n\s*.*){50,}",
                "severity": "medium",
                "category": "best_practice",
                "message": "Function appears to be very large",
                "suggestion": "Consider breaking down large functions into smaller, more focused functions",
                "languages": ["python"],
                "enabled": True,
                "confidence": 0.6
            },
            {
                "id": "magic_numbers",
                "name": "Magic Numbers",
                "description": "Detect magic numbers that should be constants",
                "pattern": r"(?<![a-zA-Z0-9_])(42|100|1000|3600|86400)(?![a-zA-Z0-9_])",
                "severity": "low",
                "category": "style",
                "message": "Magic number detected",
                "suggestion": "Consider using named constants instead of magic numbers",
                "languages": ["python", "javascript", "java", "csharp"],
                "enabled": False,  # Disabled by default as it can be noisy
                "confidence": 0.5
            },
            {
                "id": "error_handling_missing",
                "name": "Missing Error Handling",
                "description": "Detect operations that should have error handling",
                "pattern": r"(fetch|axios|http)\s*\([^)]+\)(?!\s*\.catch)",
                "severity": "medium",
                "category": "bug",
                "message": "HTTP request without error handling",
                "suggestion": "Add error handling for HTTP requests",
                "languages": ["javascript", "typescript"],
                "enabled": True,
                "confidence": 0.7
            },
            {
                "id": "deprecated_function",
                "name": "Deprecated Function Usage",
                "description": "Detect usage of deprecated functions",
                "pattern": r"(escape|unescape|String\.prototype\.substr)",
                "severity": "medium",
                "category": "best_practice",
                "message": "Deprecated function usage detected",
                "suggestion": "Use modern alternatives to deprecated functions",
                "languages": ["javascript", "typescript"],
                "enabled": True,
                "confidence": 0.8
            }
        ]
        
        config = {
            "version": "1.0",
            "organization": "My Organization",
            "description": "Custom coding rules for AI code review",
            "custom_rules": default_rules
        }
        
        with open(self.config_path, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)
        
        print(f"Created default rules configuration: {self.config_path}")
        self.load_rules()
    
    def get_rules_for_language(self, language: str) -> List[CustomRule]:
        """Get all enabled rules for a specific language"""
        return [
            rule for rule in self.rules.values()
            if rule.enabled and (not rule.languages or language in rule.languages)
        ]
    
    def add_rule(self, rule: CustomRule):
        """Add a new custom rule"""
        self.rules[rule.id] = rule
        self.save_rules()
    
    def update_rule(self, rule_id: str, **kwargs):
        """Update an existing rule"""
        if rule_id in self.rules:
            rule = self.rules[rule_id]
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            self.save_rules()
    
    def disable_rule(self, rule_id: str):
        """Disable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            self.save_rules()
    
    def enable_rule(self, rule_id: str):
        """Enable a rule"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            self.save_rules()
    
    def save_rules(self):
        """Save current rules to configuration file"""
        config = {
            "version": "1.0",
            "organization": "My Organization",
            "description": "Custom coding rules for AI code review",
            "custom_rules": [
                {
                    "id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "pattern": rule.pattern,
                    "severity": rule.severity,
                    "category": rule.category,
                    "message": rule.message,
                    "suggestion": rule.suggestion,
                    "languages": rule.languages,
                    "enabled": rule.enabled,
                    "confidence": rule.confidence
                }
                for rule in self.rules.values()
            ]
        }
        
        with open(self.config_path, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)
    
    def get_rules_summary(self) -> Dict:
        """Get summary of rules configuration"""
        enabled_rules = [rule for rule in self.rules.values() if rule.enabled]
        
        by_severity = {}
        by_category = {}
        by_language = {}
        
        for rule in enabled_rules:
            # Count by severity
            by_severity[rule.severity] = by_severity.get(rule.severity, 0) + 1
            
            # Count by category
            by_category[rule.category] = by_category.get(rule.category, 0) + 1
            
            # Count by language
            for lang in rule.languages:
                by_language[lang] = by_language.get(lang, 0) + 1
        
        return {
            "total_rules": len(self.rules),
            "enabled_rules": len(enabled_rules),
            "disabled_rules": len(self.rules) - len(enabled_rules),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_language": by_language
        }

# Integration with the main analyzer
def integrate_custom_rules(ai_reviewer_instance):
    """Integrate custom rules with the AI reviewer"""
    
    rules_manager = CustomRulesManager()
    
    # Add custom rules analysis to the existing _pattern_analysis method
    def enhanced_pattern_analysis(self, diff_lines, language, lang_config):
        """Enhanced pattern analysis including custom rules"""
        issues = []
        
        # Original pattern analysis
        patterns = lang_config.get('patterns', {})
        for line_num, line_content in diff_lines:
            for category, category_patterns in patterns.items():
                for pattern, message in category_patterns:
                    if re.search(pattern, line_content, re.IGNORECASE):
                        severity = "high" if category == "security" else "medium"
                        issues.append(CodeIssue(
                            line_number=line_num,
                            severity=severity,
                            category=category,
                            message=message,
                            suggestion=f"Review and fix this {category} issue",
                            rule_id=f"pattern_{category}_{len(issues)}",
                            confidence=0.8,
                            impact_score=5
                        ))
        
        # Custom rules analysis
        custom_rules = rules_manager.get_rules_for_language(language.value)
        
        for line_num, line_content in diff_lines:
            for rule in custom_rules:
                try:
                    if re.search(rule.pattern, line_content, re.IGNORECASE):
                        issues.append(CodeIssue(
                            line_number=line_num,
                            severity=rule.severity,
                            category=rule.category,
                            message=rule.message,
                            suggestion=rule.suggestion,
                            rule_id=rule.id,
                            confidence=rule.confidence,
                            impact_score={"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}.get(rule.severity, 5)
                        ))
                except re.error as e:
                    print(f"Invalid regex pattern in rule {rule.id}: {e}")
        
        return issues
    
    # Replace the original method
    ai_reviewer_instance._pattern_analysis = enhanced_pattern_analysis.__get__(ai_reviewer_instance, type(ai_reviewer_instance))
    
    return rules_manager

# Example usage and API endpoints for rule management
def create_rules_api_endpoints(app, rules_manager: CustomRulesManager):
    """Add API endpoints for managing custom rules"""
    
    @app.get("/api/rules")
    async def get_rules():
        """Get all custom rules"""
        return {
            "rules": [
                {
                    "id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity,
                    "category": rule.category,
                    "languages": rule.languages,
                    "enabled": rule.enabled,
                    "confidence": rule.confidence
                }
                for rule in rules_manager.rules.values()
            ],
            "summary": rules_manager.get_rules_summary()
        }
    
    @app.post("/api/rules")
    async def create_rule(rule_data: dict):
        """Create a new custom rule"""
        try:
            rule = CustomRule(**rule_data)
            rules_manager.add_rule(rule)
            return {"status": "success", "message": f"Rule {rule.id} created"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    @app.put("/api/rules/{rule_id}")
    async def update_rule(rule_id: str, updates: dict):
        """Update an existing rule"""
        try:
            rules_manager.update_rule(rule_id, **updates)
            return {"status": "success", "message": f"Rule {rule_id} updated"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    @app.post("/api/rules/{rule_id}/enable")
    async def enable_rule(rule_id: str):
        """Enable a rule"""
        rules_manager.enable_rule(rule_id)
        return {"status": "success", "message": f"Rule {rule_id} enabled"}
    
    @app.post("/api/rules/{rule_id}/disable")
    async def disable_rule(rule_id: str):
        """Disable a rule"""
        rules_manager.disable_rule(rule_id)
        return {"status": "success", "message": f"Rule {rule_id} disabled"}
    
    @app.get("/api/rules/summary")
    async def get_rules_summary():
        """Get rules configuration summary"""
        return rules_manager.get_rules_summary()

if __name__ == "__main__":
    # Example usage
    rules_manager = CustomRulesManager()
    print("Custom Rules Manager initialized")
    print(f"Loaded {len(rules_manager.rules)} rules")
    print("\nRules summary:")
    print(json.dumps(rules_manager.get_rules_summary(), indent=2))