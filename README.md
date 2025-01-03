### **Rethinking Authentication Security in AI-Generated Code**

Authors: Gurjot Singh, Prach Chantasantitam
Institution: University of Waterloo, Ontario, Canada
Contact: gurjot.singh1@uwaterloo.ca | pchantas@uwaterloo.ca

📖 Abstract

Authentication is a cornerstone of secure software systems, but vulnerabilities often arise from improperly implemented source code. This project evaluates the security of authentication-related code generated by AI-driven tools like GitHub Copilot and ChatGPT. Using Retrieval-Augmented Generation (RAG)-based compliance testing and penetration testing, we explore vulnerabilities such as weak password management and insecure multi-factor authentication (MFA). This study highlights the potential for enhancing AI tools to generate robust, NIST-compliant authentication workflows.

🚀 Research Goals

Evaluate Security Performance: Analyze AI-generated code for adherence to modern security standards like NIST and OWASP.
Enhance Prompt Engineering: Study how prompt specificity impacts the security of generated code.
Test RAG's Effectiveness: Use RAG to automate compliance checks against NIST guidelines.
Conduct Penetration Testing: Examine the resilience of AI-generated code to common attacks, including SQL injection and XSS.
🛠️ Methodology

1. Tool Selection
We evaluated four AI-driven coding tools:

GitHub Copilot
Codeium
CodeWhisperer
ChatGPT

2. Prompt Engineering
Developed basic and advanced prompts to analyze AI's intrinsic security awareness:

Basic prompts focus on general functionality.
Advanced prompts emphasize "secure" code and adherence to "NIST Guidelines."

3. Compliance Testing with RAG
Automated the assessment of NIST SP 800-63B adherence using:

NotebookLM for guideline parsing.
ChatGPT-4 for evaluation and reporting.

4. Penetration Testing
Used OWASP ZAP to identify vulnerabilities in generated code, including:

SQL Injection
Cross-Site Scripting (XSS)
Token Hijacking

5. Comparative Analysis
Compared outputs to identify strengths and weaknesses, providing actionable recommendations.

📊 Results

### **Common Vulnerabilities Identified**
- Insecure password management.
- Weak MFA implementations using non-cryptographic randomness.
- Lack of rate limiting, allowing brute-force attacks.

### **MFA Code Delivery Methods**

| **Tool**           | **Delivery Medium** |
|---------------------|---------------------|
| GitHub Copilot      | SMS (Twilio)       |
| CodeWhisperer       | SMS (Twilio)       |
| Codeium             | TOTP (PyOTP)       |
| ChatGPT             | Email (SMTP)       |


🔬 Key Findings

Insecure Defaults: Tools rely heavily on default configurations, often not secure.
Cryptographic Choices: ChatGPT demonstrated the best practices by using Argon2, whereas others used weaker algorithms like Bcrypt or PBKDF2.
RAG Effectiveness: RAG effectively identifies guideline violations but struggles with nuanced security concepts like encryption vs. hashing.
🧑‍💻 How to Use This Repository

## 🧑‍💻 Getting Started

### **Prerequisites**
- Python 3.9+
- Flask, OWASP ZAP, and NotebookLM installed.

### **Setup Instructions**
1. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-username>/rethinking-authentication-security.git
   cd rethinking-authentication-security
   
Then use the codes provided under each section.

📚 References

NIST SP 800-63B Guidelines: NIST Guidelines (Mentioned in the PDF)
OWASP Cheat Sheets: Authentication Cheat Sheet (Mentioned in the PDF)

🎯 Future Work

Extend RAG compliance checks for nuanced vulnerabilities.
Incorporate fine-tuned security-specific AI models.
Optimize MFA code generation with secure randomness and validation mechanisms.
