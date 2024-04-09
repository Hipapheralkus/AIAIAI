# AIAIAI (An Incredibly Annoying, Insufferable Authentication Implementation)

This web application is meant to demonstrate harder session management. The initial goal is to learn how to properly set up Burp Suite, but feel free to experiment, contribute, and make it harder:)

Credentials are hardcoded:
```
USERNAME = 'admin'
PASSWORD = 'password'
SECRET_KEY = 'secret123'
```

Concerning vulnerabilities, the POST to /hi2 results in stored XSS which can be access on /names. 

If you are interested, check out a deep dive into topics of Session Management and Session Macros in Burp Suite

[![Youtube Live Demo](https://github.com/Hipapheralkus/AIAIAI/assets/4717664/f81b7530-a237-43e9-9ad8-03fd1b9e3744)](https://youtu.be/mM3LR9KQePI)
