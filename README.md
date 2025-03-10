### **Unvalidated Redirects and Forwards**

**Unvalidated Redirects and Forwards** is a type of web vulnerability where a web application allows an attacker to manipulate the destination of a redirect or forward, potentially leading to malicious outcomes. This vulnerability occurs when user input is used to specify the location to which a user is redirected, but the server doesn't properly validate or sanitize that input.

This vulnerability can have serious consequences, such as phishing, redirecting users to malicious sites, or exposing sensitive data to unauthorized third parties.

### **Key Concepts**

1. **Redirects**:
   - A **redirect** is when a server responds to a user's request by sending them to a different URL. Common examples include HTTP status codes like `301 Moved Permanently` or `302 Found`, which instruct browsers to go to a new location.
   - Attackers can exploit unvalidated redirects to send users to malicious websites.

2. **Forwards**:
   - A **forward** is when a server internally forwards the request to another URL or resource, typically on the same server or application. This often happens behind the scenes in the server-side code.
   - An attacker can manipulate this by tricking the server into forwarding a request to a malicious location or performing unauthorized actions.

---

### **How Unvalidated Redirects and Forwards Work**

1. **Unvalidated Redirects**:
   When a web application accepts user input to determine the redirect destination, and this input is not validated or sanitized, attackers can manipulate this to redirect users to malicious websites.

   Example: A URL parameter `redirect` specifies where the user should be redirected after completing an action. If the web application doesn't validate this parameter, attackers can inject arbitrary URLs.

2. **Unvalidated Forwards**:
   In web applications, forwards are typically used to pass control to another resource on the server, such as another page, template, or processing function. If the application forwards based on user-controlled input without proper validation, an attacker can force the application to forward to unintended or dangerous destinations.

---

### **Example of Unvalidated Redirect (Attacker Exploiting Redirect to Phishing Site)**

#### Vulnerable Code Example:

Imagine an application where users can request a password reset, and after the password is reset, they are redirected to a URL provided by the `redirect_url` parameter.

```python
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Password reset logic here

        # Redirect to the provided URL (without validation)
        redirect_url = request.args.get('redirect_url')
        return redirect(redirect_url)

    return '''
        <form method="post">
            <label for="email">Email:</label>
            <input type="email" name="email" required>
            <button type="submit">Reset Password</button>
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
```

In this example, after the user resets their password, the server redirects them to the URL provided in the `redirect_url` parameter. If the `redirect_url` is not properly validated, an attacker could trick the user into being redirected to a malicious site, such as a phishing page.

#### Attack Scenario:

An attacker sends a link to a user, e.g.,

```
http://vulnerable-website.com/reset_password?redirect_url=http://malicious-site.com/phishing-page
```

After the user resets their password, they will be redirected to `http://malicious-site.com/phishing-page`, which could trick them into entering their credentials, allowing the attacker to steal sensitive information.

---

### **Consequences of Unvalidated Redirects and Forwards**

1. **Phishing Attacks**: Attackers can redirect users to malicious websites that mimic legitimate sites, tricking users into entering their sensitive information (e.g., login credentials, credit card numbers).
   
2. **Malware Distribution**: Attackers can redirect users to websites that distribute malware, infecting their devices.
   
3. **Denial of Service (DoS)**: In some cases, attackers could create a redirection loop or forward to resource-intensive locations, causing denial-of-service attacks.

4. **Bypassing Security Controls**: By manipulating redirects or forwards, attackers might bypass security restrictions or access sensitive resources.

5. **Loss of Trust**: Redirecting users to untrusted sites can severely damage the reputation and trustworthiness of the affected website.

---

### **Mitigating Unvalidated Redirects and Forwards**

1. **Avoid Using User Input for Redirect URLs**:
   - Never rely on user input (like query parameters or form inputs) to determine redirect or forward destinations. If possible, avoid redirects altogether.
   
2. **Validate Redirect URLs**:
   - If redirects are necessary, ensure that the URL is valid, belongs to a trusted domain, and does not contain potentially harmful components (like `javascript:` URLs).
   - Use a whitelist of allowed domains to ensure that the user can only be redirected to safe, known locations.
   
3. **Relative URLs**:
   - If you must allow redirection, use only relative URLs (e.g., `/home` or `/dashboard`) instead of full URLs. This prevents attackers from redirecting users to external sites.

4. **URL Rewriting/Canonicalization**:
   - Use strict URL rewriting to canonicalize the URLs and ensure they do not lead to malicious locations (e.g., normalize URLs to prevent directory traversal attacks).

5. **Redirect to a Confirmation Page**:
   - Rather than redirecting users directly to a destination after an action, redirect them to a confirmation page first. This gives the user a chance to review their actions and verify the next destination.

6. **Use Anti-CSRF Tokens in Redirects**:
   - Anti-CSRF tokens can prevent attackers from manipulating redirects as part of a larger CSRF attack.

7. **Check `Referer` and `Origin` Headers**:
   - If your application handles redirects or forwards, verify that the `Referer` or `Origin` headers are from a trusted source before allowing the request to proceed.

---

### **Example of Fixing Unvalidated Redirect (Redirect Validation)**

In the fixed version of the earlier code, we can add a whitelist of trusted URLs that the server is allowed to redirect to. Any URL outside this list will not be redirected to.

#### Fixed Code Example:

```python
from flask import Flask, request, redirect, abort

app = Flask(__name__)

# Whitelist of allowed domains for redirect
ALLOWED_REDIRECTS = ["https://trusted-site.com", "https://another-trusted-site.com"]

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        # Password reset logic here

        # Get the redirect URL from the query parameter
        redirect_url = request.args.get('redirect_url')

        # Check if the redirect URL is in the allowed list
        if redirect_url and any(redirect_url.startswith(domain) for domain in ALLOWED_REDIRECTS):
            return redirect(redirect_url)
        else:
            abort(400, "Invalid redirect URL")

    return '''
        <form method="post">
            <label for="email">Email:</label>
            <input type="email" name="email" required>
            <button type="submit">Reset Password</button>
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)
```

#### Explanation of the Fix:
- **Whitelist of Allowed Domains**: The code checks if the `redirect_url` starts with any domain in the `ALLOWED_REDIRECTS` list. If the destination URL is not in this list, the request is aborted with a `400 Bad Request` response.
- **Secure Redirect**: The redirect is now validated before the user is sent anywhere, preventing malicious redirects.

---

### **Conclusion**

Unvalidated redirects and forwards are dangerous vulnerabilities that can lead to phishing, malware distribution, and bypassing security controls. To mitigate these risks:
- Avoid allowing users to specify URLs for redirects and forwards.
- Validate any URLs that are provided and ensure they are from trusted sources (e.g., using a whitelist).
- Consider using relative URLs, implementing anti-CSRF tokens, and verifying `Referer` or `Origin` headers.

By implementing these security practices, you can significantly reduce the risk of unvalidated redirects and forwards in your web applications.
