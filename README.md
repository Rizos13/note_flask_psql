# Note_flask

#### This project is a secure web application written in flask using a postgresql database.

Cross-site request forgery (csrf) is a type of attack where an attacker can force a user to perform an unwanted action on a trusted site. in this project, csrf protection has been implemented using the flask_wtf library.

##### Implementation:

· The csrfprotect extension for flask is used, which automatically adds a csrf token to forms and checks it on every request, preventing the execution of forged requests. 

· When a csrf error occurs, the application handles it with a custom handler. 

· Csrf protection requires all forms and data-changing requests to include a csrf token, making attacks impossible without the appropriate token. 

· Csrf tokens in the application are tied to the user’s session and change with each request, preventing token reuse and enhancing security.

```
from flask_wtf import csrfprotect
from flask_wtf.csrf import csrferror

csrf = csrfprotect(app)

@app.errorhandler(csrferror)
def handle_csrf_error(e):
    return f"csrf error: {e.description}", 400
```

##### Additional advantages:

· Csrf tokens are transmitted securely and stored only on the server side, making them difficult to forge. 

· Csrf errors are logged to monitor potential attack attempts.

His ensures a high level of protection against csrf attacks and maintains the integrity of actions performed by users on the site.