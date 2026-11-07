# XPath Injection (CWE-643) Defense Specification

## 1. Overview

XPath Injection occurs when an application constructs XML Path Language (XPath) queries using unescaped user input. Similar to SQL injection, malicious input can alter query logic, allowing attackers to navigate unauthorized sections of an XML document, bypass authentication logic, or extract sensitive attributes.

---

## 2. Attack Vectors

Given a naive query:
```xpath
//user[username='INPUT_USER' and password='INPUT_PASS']
```

Supplying an input payload such as `' or '1'='1` forces the predicate to evaluate to `True`, selecting all user nodes regardless of credentials.

---

## 3. Defense Implementation

1. **Parameterized Variables (XPath 2.0 / 3.0 / lxml)**:
   Use variable binding APIs where input values are treated purely as string literals rather than executable expressions.
2. **Strict Character Validation with `XpathStructureValidator`**:
   Before embedding values into XPath expressions, verify that characters such as `'`, `"`, `[`, `]`, `/`, and boolean keywords `or`/`and` are absent.
3. **Canonical Normalization**:
   Reject inputs containing double slashes or XML comment delimiters (`<!-- -->`) that could truncate predicate logic.
