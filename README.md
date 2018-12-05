# Mikrotik-API
This repository contains two python files. The first one, mikrotik_api_orig.py is adopted from the official Mikrotik Website.
It works fine on a Linux host. However, on a Windows host, due to limitations of select.select on Windows, it is useless.
My mikrotik_api.py works on any architecture. Furthermore, several fallacies of the original API were removed and new features were added.

The code accepts up to 4 arguments:
The first argument: IP address of the Mikrotik Router
The second argument: Port of the Router (This is one the enhancements of the code)
The third argument (optional): username
The fourth argument (optional): password

If two arguments are provided, the api tries to login with "admin" and blank password credentioals.
If three arguments are provided, the api logs in with the third argument as the username and blank password.

To quit the api enter {quit}. (This another enhancement of the code)
