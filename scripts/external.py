import os
import sysconfig

if __name__ == "__main__":
    try:
        lib_path = sysconfig.get_path("stdlib", sysconfig.get_default_scheme())

    except AttributeError:
        lib_path = sysconfig.get_path("stdlib")

    if os.path.isfile(os.path.join(lib_path, "EXTERNALLY-MANAGED")):
        print("--break-system-packages")
    else:
        print("")
