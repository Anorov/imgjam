imgjam.py
======

An ARP + DNS spoofing script for a local switched network that effectively "jams" all requests with a specified image, or randomly chosen image.

Sets up a lightweight HTTP server, and intercepts all HTTP traffic so that a specified image is returned as the response to all HTTP requests. Also works for HTTPS URLs, though a "self-signed certificate" warning will appear for the user.

Uses `wlan0` as the default network interface.

This is an old project and may have bugs.

Usage
=====

    ./imgjam.py [filename.jpg|dir_of_files] [timeout in seconds: default infinity]

**Example**

    ./imgjam.py cool_crow.jpg
    
    ./imgjam.py images 6000
