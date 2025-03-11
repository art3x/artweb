# ArtWeb

ArtWeb is a tiny web server written in C.
Based on awesome cpp-httplib project: https://github.com/yhirose/cpp-httplib

![ArtWeb](images/artweb.png)

## Features

* Upload and Download files
* Multiplatform (Windows and Linux)
* HTTP Basic authentication support

## Usage

```
Options:
  -h, --help          Print this help message
  --port PORT         Set the port (default: 80)
  --pass PASSWORD     Enable HTTP Basic authentication (username is always 'admin')
                      If not provided, no authentication is enforced.
```