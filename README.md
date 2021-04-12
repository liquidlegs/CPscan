# CPscan
A basic port scanner written in C using winapi's

![CPScan screenshot](/Assets/cp.png)

### How to compile executable
Assuming you already have gcc mingw installed with the environment variables setup. Enter the following command into your terminal.
```
gcc Whatever/you/path/toYourDirectoryIs/CPScan/portScanTest.c -lws2_32 -ldnsapi -o Your/Directory/CPScan/portScanTest.exe
```
