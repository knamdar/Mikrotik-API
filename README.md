# Mikrotik-API
This repository contains two python files. The first one, mikrotik_api_orig.py is adopted from the official Mikrotik Website.
It works fine on a Linux host. However, on a Windows host, due to limitations of select.select on Windows, it is useless.
My mikrotik_api.py works on any architecture. Furthermore, several fallacies of the original API were removed and new features were added.
The code accepts up to 4 arguments.
