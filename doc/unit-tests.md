### Compiling/running unit tests

Unit tests are not part of the default build but can be built on demand.

All the unit tests can be built and run with a single command: `ninja check`.

#### lotusd unit tests

The `lotusd` unit tests can be built with `ninja test_lotus`.
They can also be built and run in a single command with `ninja check-bitcoin`.

To run the `lotusd` tests manually, launch `src/test/test_lotus`.

To add more `lotusd` tests, add `BOOST_AUTO_TEST_CASE` functions to the
existing .cpp files in the `src/test/` directory or add new .cpp files that
implement new `BOOST_AUTO_TEST_SUITE` sections.

#### lotus-qt unit tests

The `lotus-qt` tests can be built with `ninja test_lotus-qt` or
built and run in a single command with `ninja check-lotus-qt`.

To run the `lotus-qt` tests manually, launch `src/qt/test/test_lotus-qt`.

To add more `lotus-qt` tests, add them to the `src/qt/test/` directory and
the `src/qt/test/test_main.cpp` file.

#### lotus-seeder unit tests

The `lotus-seeder` unit tests can be built with `ninja test-seeder` or
built and run in a single command with `ninja check-seeder`.

To run the `lotus-seeder` tests manually, launch
`src/seeder/test/test-seeder`.

To add more `lotus-seeder` tests, add `BOOST_AUTO_TEST_CASE` functions to the
existing .cpp files in the `src/seeder/test/` directory or add new .cpp files
that implement new `BOOST_AUTO_TEST_SUITE` sections.

### Running individual tests

`test_lotus` has some built-in command-line arguments; for
example, to run just the `getarg_tests` verbosely:

    test_lotus --log_level=all --run_test=getarg_tests

... or to run just the doubledash test:

    test_lotus --run_test=getarg_tests/doubledash

Run `test_lotus --help` for the full list.

### Adding test cases

The build system is setup to compile an executable called `test_lotus`
that runs all of the unit tests. The main source file for the test library
is found in `util/setup_common.cpp`. To add a new unit test file to our
test suite you need to add the file to `src/test/CMakeLists.txt`.
The pattern is to create one test file for each class or source file for
which you want to create unit tests. The file naming convention is
`<source_filename>_tests.cpp` and such files should wrap their tests in
a test suite called `<source_filename>_tests`. For an example of this pattern,
see `uint256_tests.cpp`.

For further reading, I found the following websites to be helpful in
explaining how the boost unit test framework works:
[https://legalizeadulthood.wordpress.com/2009/07/04/c-unit-tests-with-boost-test-part-1/](https://legalizeadulthood.wordpress.com/2009/07/04/c-unit-tests-with-boost-test-part-1/)
[http://www.alittlemadness.com/2009/03/31/c-unit-testing-with-boosttest/](http://archive.is/dRBGf)

### Logging and debugging in unit tests

To write to logs from unit tests you need to use specific message methods
provided by Boost. The simplest is `BOOST_TEST_MESSAGE`.

For debugging you can launch the test_lotus executable with `gdb`or `lldb` and
start debugging, just like you would with lotusd.

This is a simple example of debugging unit tests with GDB on Linux:
```
cd /build/src/test
gdb test_lotus
break interpreter.cpp:295  # No path is necessary, just the file name and line number
run
# GDB hits the breakpoint
p/x opcode  # print the value of the variable (in this case, opcode) in hex
c           # continue
```

This is a simple example of debugging unit tests with LLDB (OSX or Linux):
```
cd /build/src/test
lldb -- test_lotus
break set --file interpreter.cpp --line 295
run
```
