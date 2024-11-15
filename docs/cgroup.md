# 需要 V2

```
mount | grep cgroup2

mkdir /sys/fs/cgroup/foo

RUST_LOG=info cargo xtask run

bash -c "echo \$$ >> /sys/fs/cgroup/foo/cgroup.procs && curl 1.1.1.1"

bash -c "echo \$$ >> /sys/fs/cgroup/foo/cgroup.procs && curl google.com"
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="http://www.google.com/">here</A>.
</BODY></HTML>


```