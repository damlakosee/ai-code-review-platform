# 🤝 Contributing to AI Code Review Platform

First off, thank you for considering contributing to the AI Code Review Platform! It's people like you that make this project a great tool for developers worldwide.

---

## 🎯 Ways to Contribute

### 🐛 Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you are creating a bug report, please include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps which reproduce the problem
- Provide specific examples to demonstrate the steps
- Describe the behavior you observed and what behavior you expected
- Include screenshots and animated GIFs if relevant
- Include your environment details (OS, Python version, etc.)

---

### ✨ Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- Use a clear and descriptive title
- Provide a step-by-step description of the suggested enhancement
- Provide specific examples to demonstrate the enhancement
- Describe the current behavior and explain the expected behavior
- Explain why this enhancement would be useful

---

### 🔧 Code Contributions

#### Setting Up Development Environment

```bash
# Fork the repository and clone your fork:
git clone https://github.com/yourusername/ai-code-review-platform.git
cd ai-code-review-platform

# Create a virtual environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies including development tools:
pip install -r requirements.txt
pip install pyyaml  # For custom rules

# Copy environment variables:
cp .env.example .env
# Edit .env with your test configuration

# Run tests to ensure everything works:
python main.py
# Should start without errors
```

---

#### Development Workflow

```bash
# Create a feature branch from main:
git checkout -b feature/your-feature-name

# Make your changes and test them:
python main.py  # Start the app
curl http://localhost:8000/health  # Test health endpoint

# Commit your changes:
git add .
git commit -m "feat: add amazing new feature"

# Push to your fork:
git push origin feature/your-feature-name
```

Then, open a **Pull Request** with a clear title and description.

---

## 📋 Coding Standards

### Python Code Style

We use **Black** for code formatting:

```bash
# Format code (install with: pip install black)
black main.py custom_rules.py

# Check code style
python -m py_compile main.py
```

### File Organization

- Keep functions focused
- Use type hints
- Add docstrings
- Handle errors gracefully
- Follow PEP 8 guidelines

---

### Commit Message Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

Examples:

- `feat: add custom rule for detecting hardcoded secrets`
- `fix: resolve dashboard loading issue on mobile devices`
- `docs: update API documentation with new endpoints`

---

## 🧪 Testing

### Manual Testing

```bash
# 1. Start the application
python main.py

# 2. Visit dashboard
http://localhost:8000/dashboard

# 3. Test API endpoints
curl http://localhost:8000/health
curl http://localhost:8000/api/reviews
curl http://localhost:8000/api/stats
curl http://localhost:8000/api/rules/summary

# 4. Try different port (optional)
uvicorn main:app --host 0.0.0.0 --port 8080
```

### Testing Checklist

- [ ] App starts without errors  
- [ ] Dashboard loads properly  
- [ ] API endpoints return valid responses  
- [ ] Custom rules system initializes  
- [ ] WebSocket works  
- [ ] Code style is consistent  
- [ ] No syntax errors  

---

## 📚 Documentation

### Code Documentation

```python
def analyze_code_quality(code_lines: List[str], language: str) -> Dict[str, Any]:
    """
    Analyze code quality metrics for given code lines.
    """
```

### API Documentation

```python
@app.get("/api/example")
async def example_endpoint(param: str = Query(..., description="Example parameter")):
    """
    Example endpoint showing FastAPI docs.
    """
```

---

## 🚀 Pull Request Process

- Ensure your PR has a clear title and description  
- Link related issues (e.g., "Fixes #123")  
- Update documentation as needed  
- Run manual tests  
- Follow code style guidelines  
- Request review from maintainers  

---

## 🧪 PR Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Application starts
- [ ] Dashboard loads
- [ ] API works
- [ ] Manual testing done

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed
- [ ] Code is commented
- [ ] Docs updated
```

---

## 🏗️ Architecture Guidelines

### Adding New Features

- Create an issue first  
- Ensure backward compatibility  
- Add tests  
- Update docs and config  

### Performance Considerations

- Use async I/O  
- Respect API rate limits  
- Watch memory usage  
- Handle failures gracefully  

### Security Considerations

- Validate inputs  
- Don't commit secrets  
- Avoid leaking errors  
- Keep dependencies secure  

---

## 🌟 Recognition

Contributors will be recognized in:

- README section  
- Release notes  
- GitHub achievements  
- Community showcases  

---

## 📞 Getting Help

- GitHub Discussions  
- GitHub Issues  
- README and code comments  

If you're new:

- Start with README  
- Explore the code  
- Try the demo  
- Ask questions  

---

## 📜 Code of Conduct

We pledge to make participation a harassment-free experience for everyone.

### Our Standards

- Inclusive language  
- Respect differing views  
- Accept feedback  
- Be kind  

### Enforcement

Violations may be reported and will be handled fairly.

---

## 🎉 Thank You

Your contributions make this project better for everyone.  
Happy coding! 🚀
