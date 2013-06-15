GLSync
======

This is a readme file for glsync hack, which enforces glXSwapBuffers to synchronize GPU with CPU (e.g. empty the command buffer)
This project is a shameless fork of elfhacks - an excelent work of Pyry Haulos - all credit goes to him.

Building
--------

```bash
mkdir build
cd build
cmake ..
make
```

This will (hopefully) produce libglsync.so and libglsync32.so, which should be LD_PRELOADed with the application that needs to be amended.

Running
-------

Usually it should suffice to do:

```bash
LD_PRELOAD=PATH_TO/libglsync.so executable
```
or

```bash
LD_PRELOAD=PATH_TO/libglsync32.so 32bit_executable
```

for 32bit executables.


Known issues
------------

Left4Dead2 does not work with this lib ("Could not load library matchmaking").