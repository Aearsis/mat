## Match-Action Tables

This is a demonstration implementation of the subsystem proposed in my Master
thesis, under working title Match-Action Tables, MAT for short.

The code is written in a kernel-like way, in an environment that simulates the
Linux kernel. The subsystem code is therefore similar to what it would look
like if implemented as a module, but can be run and tested in userspace.

### Usage

First, you have to compile the sources. On Linux, it should be fairly easy:

```bash
$ make
````

Then, several testcases are created under the `tests/` directory. To run them
all and check whether everything is OK:

```bash
$ ./test.sh
```

The source code of the tests should be the starting point of your journey
through the implementation. They are written as scenarios, showing the expected
usage of the subsystem.
