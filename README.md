# NetPanzer 'masterserver' v.1.0

Listens to port 28900 for 'heartbeat' messages from netpanzer gameservers.

Provides a [list of live games](https://netpanzer.io/servers.html).

Works with NetPanzer 0.8.7 version and higher.

System firewall must allow connections to port 28900.

both udp and tcp (udp is used for a quick challenge echo request).

## Compiling:

Libs required: libevent (the 'dev' too).

You can use [meson](https://mesonbuild.com/) or compile with:

    gcc -s -O2 -Wall ./npms.c -o npms -L. -levent

Test it with:

    echo -n "\\list\\gamename\\netpanzer\\final\\" | nc  127.0.0.1 28900

Should answer '\final\' even if list is empty.

(After start it might take up to 5 mins to populate internal array with
existing live gameservers.)
