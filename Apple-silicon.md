# Apple silicon

## Install libusb
Make sure you have installed brew (a elegent package manager for macOS, [https://brew.sh/](https://brew.sh/)).
``` brew install libusb```

If you encount following issue:
```
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/Library/Frameworks/Python.framework/Versions/3.9/lib/python3.9/site-packages/usb/core.py", line 1299, in find
    raise NoBackendError('No backend available')
usb.core.NoBackendError: No backend available
```
You can following this link [issues/355](https://github.com/pyusb/pyusb/issues/355#issuecomment-974726078) to solve it.
```
ln -s /opt/homebrew/lib/libusb-1.0.0.dylib //usr/local/lib/libusb.dylib
```
After this, you can validate libusb whether works as weel by executing following command.
```
$ /opt/homebrew/opt/python@3.8/bin/python3 -c "import ctypes.util; print(ctypes.util.find_library('usb'))"
/opt/homebrew/lib/libusb.dylib
```