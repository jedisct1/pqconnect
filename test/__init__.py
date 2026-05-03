import os

if 'CI' not in os.environ:
    os.environ['CI'] = "0"
if 'QEMU' not in os.environ:
    os.environ['QEMU'] = "0"
