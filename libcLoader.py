import os
import sys
import platform
import requests
import subprocess
import shutil
import tempfile
from tqdm import tqdm

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
    url = f"https://launchpad.net/ubuntu/+archive/primary/+files/libc6_{version_number}-0ubuntu{seqnum}_{arch_base}.deb"
    filename = f"libc6_{version_number}-0ubuntu{seqnum}_{arch_base}.deb"
    print(f"[+] \033[92mDownloading {filename}...\033[0m")
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
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

def main():
    version_number = sys.argv[1] if len(sys.argv) > 1 else input("Enter the version number (e.g., 2.34): ")
    arch_base = get_architecture()
    if not arch_base:
        print("[-] \033[91mUnsupported architecture.\033[0m")
        return

    seqnum = 0
    while seqnum < 10:
        deb_file = download_file(version_number, seqnum, arch_base)
        if deb_file:
            with tempfile.TemporaryDirectory() as tmp_dir:
                extract_deb(deb_file, tmp_dir)
                libc_so_file = os.path.join(tmp_dir, "lib/x86_64-linux-gnu/libc.so.6")
                if os.path.exists(libc_so_file):
                    shutil.copy(libc_so_file, ".")
                    print("[+] \033[92mCopied libc.so.6 to current directory\033[0m")
                else:
                    print("[-] \033[93mlibc.so.6 not found\033[0m in extracted files")
                os.remove(deb_file)
                print(f"[+] \033[92mDeleted {deb_file}\033[0m")
                break
        seqnum += 1

if __name__ == "__main__":
    main()
