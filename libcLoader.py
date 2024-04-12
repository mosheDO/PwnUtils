#!/usr/bin/env python3

import os
import sys
import platform
import requests
import shutil
import tempfile
from pwn import *
from tqdm import tqdm
import argparse


ARCH_LIST = ['amd64', 'i386']
LIBC_NAME = "libc.so.6"
LIBC_LOCATION = "lib/x86_64-linux-gnu/libc.so.6"
URL_TEMPLATE = "https://launchpad.net/ubuntu/+archive/primary/+files/libc6_{version}-0ubuntu{seqnum}_{arch_base}.deb"
URL_SOLVE_SCRIPT = "https://raw.githubusercontent.com/mosheDO/PwnUtils/master/solve.py"


def get_architecture():
    machine = platform.machine()
    if machine == "x86_64":
        return "amd64"
    elif machine == "i386":
        return "i386"
    else:
        # Add more cases as needed for other architectures
        return None


def download_file(version_number, seqnum, arch_base):
    url = URL_TEMPLATE.format(version=version_number, seqnum=seqnum, arch_base=arch_base)
    filename = f"libc6_{version_number}-0ubuntu{seqnum}_{arch_base}.deb"
    print(f"[+] \033[92mDownloading {filename}...\033[0m")
    sleep(1)
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    if total_size < 1024 * 1024:  # Check if file size is below 1 MB
        print("[-] \033[91mSkipping download: File size is below 1 MB and does not match the expected size for the libc file.\033[0m")
        return None
    block_size = 1024
    progress_bar = tqdm(total=total_size, unit='B', unit_scale=True)
    with open(filename, 'wb') as file:
        for data in response.iter_content(block_size):
            progress_bar.update(len(data))
            file.write(data)
    progress_bar.close()
    if total_size != 0 and progress_bar.n != total_size:
        print(f"[-] \033[91mFailed to download {filename}\033[0m")
        return None
    else:
        print(f"[+] \033[92mDownloaded {filename}\033[0m")
        return filename


def extract_deb(deb_file, extract_dir):
    print(f"[+] \033[92mExtracting {deb_file} to {extract_dir}...\033[0m")
    subprocess.run(["dpkg", "-x", deb_file, extract_dir])


# def call_pwninit(bin_path, libc_path, ld_path=None):
#     command = ["pwninit", "--bin", bin_path, "--libc", libc_path]
#     if ld_path:
#         command.extend(["--ld", ld_path])
#     result = subprocess.run(command, capture_output=True, text=True)
#     if result.returncode == 0:
#         print("[+] \033[92mpwninit ran successfully! Ready to pwn!\033[0m")
#     else:
#         print("[-] \033[91mpwninit failed to run.\033[0m")


def call_pwninit(bin_path, libc_path, ld_path=None):
    context.log_level = 'INFO'  # Set log level to print output

    command = f"pwninit --bin {bin_path} --libc {libc_path}"
    if ld_path:
        command += f" --ld {ld_path}"
    
    # Run the pwninit command

    with process(command, shell=True) as p:
        try:
            while True:
                 if p.can_recv(timeout=1):
                    out = p.recv().decode()
                    success(p.recv())  # Receive all output from the process
                    
                    if 'writing solve.py' in out:
                        print("[+] \033[92mpwninit ran successfully! Ready to pwn!\033[0m")
                        log.success("Downloaded solve.py successfully")
                        break
                    else:
                        print(out, end='')
        except EOFError:
            pass


def download_solve_script(url):
    response = requests.get(url)
    if response.status_code == 200:
        with open("solve.py", "wb") as file:
            file.write(response.content)
        print("[+] \033[92mDownloaded solve.py successfully\033[0m")
    else:
        print("[-] \033[91mFailed to download solve.py\033[0m")


def main():
    parser = argparse.ArgumentParser(description='Download libc6 package for a specified version from the Ubuntu launchpad repository.')
    parser.add_argument('version_number', metavar='VERSION', type=str, nargs='?', help='The version number of the libc6 package')
    parser.add_argument('-a', '--arch',  type=str, nargs='?', help='The architecture of the libc6 package. If not provided,  Resolve architecture automatically.')
    parser.add_argument('-b', '--binary', type=str, help='Path to the binary file. Used for pwninit (if needed)')

    args = parser.parse_args()
    
    if args.version_number is None or args.version_number == '-h':
        parser.print_help()
        return

    if args.arch and args.arch not in ARCH_LIST:
        arch_base = input("Enter the architecture (e.g., amd64, i386): ")
        if arch_base not in ARCH_LIST:
            print("[-] \033[91mUnsupported architecture. Supported architectures are: amd64, i386\033[0m")
            return
    else:
        arch_base = get_architecture()
        if not arch_base:
            print("[-] \033[91mUnsupported architecture. Supported architectures are: ARCH_LIST\033[0m")
            return

    seqnum = 0
    while seqnum < 10:
        print("[+] \033[92mDownloading the file and verifying its integrity...\033[0m")
        deb_file = download_file(args.version_number, seqnum, arch_base)
        if deb_file:
            with tempfile.TemporaryDirectory() as tmp_dir:
                extract_deb(deb_file, tmp_dir)
                libc_so_file = os.path.join(tmp_dir, LIBC_LOCATION)
                if os.path.exists(libc_so_file):
                    shutil.copy(libc_so_file, ".")
                    print("[+] \033[92mCopied libc.so.6 to current directory\033[0m")
                    sleep(1)
                else:
                    print("[-] \033[93mlibc.so.6 not found\033[0m in extracted files")
                os.remove(deb_file)
                print(f"[+] \033[92mDeleted {deb_file}\033[0m")
                break
        seqnum += 1
    if args.binary:
        print(f"[+] \033[92mUsing pwninit with binary: '{args.binary}', and downloaded libc\033[0m")
        # Assuming LIBC_NAME is defined somewhere
        if os.path.exists(LIBC_NAME) and os.path.exists(args.binary):
            call_pwninit(bin_path=args.binary, libc_path=LIBC_NAME)
        else:
            print(f"[-] \033[91mError: {LIBC_NAME} does not exist\033[0m")
    else:
        print("[-] \033[93mNo binary file provided. Use -b/--binary to specify the binary file path\033[0m")
    download_solve_script(URL_SOLVE_SCRIPT)


if __name__ == "__main__":
    main()

