libc6 Downloader
================

This Python script downloads the libc6 package for a specified version from the Ubuntu launchpad repository. It attempts to download the package with sequence numbers from 0 to 10 and extracts the `libc.so.6` file from the downloaded package. It also provides a progress bar during the download process.

Usage
-----

You can run the script with the following command:

bashCopy code

`python script.py <version_number>`

If you don't specify the version number as a command-line argument, the script will prompt you to enter it interactively.

Requirements
------------

-   Python 3.x
-   Requests library
-   tqdm library

You can install the required libraries using pip:

```
pip install requests tqdm
```

License
-------

This project is licensed under the MIT License - see the LICENSE file for details.
