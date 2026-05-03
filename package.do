#!/usr/bin/env python3

import os
import shutil
import subprocess

version = None

with open('pyproject.toml') as f:
  for line in f:
    line = line.split()
    if len(line) < 3: continue
    if line[0] != 'version': continue
    version = line[2].replace('"','')
    break

assert version is not None
shutil.rmtree(f'package/pqconnect-{version}',ignore_errors=True)

files = subprocess.run(['git','ls-files'],check=True,capture_output=True,universal_newlines=True).stdout
files = files.splitlines()

for fn in files:
  targetfn = f'package/pqconnect-{version}/{fn}'
  targetdir = '/'.join(targetfn.split('/')[:-1])
  os.makedirs(targetdir,exist_ok=True)
  shutil.copy(fn,targetfn)

timestamp = os.stat('pyproject.toml').st_mtime_ns
os.utime(f'package/pqconnect-{version}',ns=(timestamp,timestamp))

os.chdir('package')

subprocess.run([
  'tar','--owner=root','--group=root','--sort=name',
    f'--mtime=./pqconnect-{version}',
    '-czf',f'pqconnect-{version}.tar.gz',
    f'pqconnect-{version}'
],check=True)

shutil.rmtree(f'pqconnect-{version}',ignore_errors=True)
