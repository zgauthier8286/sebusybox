Busybox for SELinux environment

## The list of works ##

### coreutils package ###
| **command** | **assignment** | **state** | **description** |
|:------------|:---------------|:----------|:----------------|
| /bin/cp     | Nakamura       | **merged** | -c, -Z option support |
| /bin/ls     | Nakamura       | **merged** | -Z option support |
| /bin/mkdir  | Yo.Sato        | **merged** | -Z option support |
| /bin/mknod  | Yo.Sato        | ready     | setfscon suppoer |
| /bin/mv     | Nakamura       | **merged** | -Z option support |
| /usr/bin/chcon | KaiGai         | **merged** | new applet      |
| /usr/bin/id | Nakamura       | **merged** | -Z option support |
| /usr/bin/install | Nakamura       | **merged** | -Z,-P option support |
| /usr/bin/mkfifo | Yo.Sato        | ready     | setfscon support |
| /usr/bin/runcon | KaiGai         | **merged** | new applet      |
| /usr/bin/stat | Yo.Sato        | **merged** | -Z option support |

### policycoreutils package ###
| **command** | **assignment** | **state** | **description** |
|:------------|:---------------|:----------|:----------------|
| /sbin/fixfiles |                |           | no plan         |
| /sbin/restorecon | Nakamura       | reviewing | new applet      |
| /sbin/setfiles | Nakamura       | reviewing | new applet      |
| /usr/bin/audit2allow |                |           | no plan         |
| /usr/bin/chcat |                |           | no plan         |
| /usr/bin/newrole |                |           |                 |
| /usr/bin/secon | Nakamura       | ready     | new applet      |
| /usr/bin/semodule\_deps |                |           | depend on libsemanege |
| /usr/bin/semodule\_expand |                |           | depend on libsemanage |
| /usr/bin/semodule\_link |                |           | depend on libsemanage |
| /usr/bin/semodule\_package |                |           | depend on libsemanage |
| /usr/sbin/audit2why |                |           | no plan         |
| /usr/sbin/genhomedircon |                |           | no plan         |
| /usr/sbin/load\_policy | Nakamura       | **merged** | new applet      |
| /usr/sbin/open\_init\_pty | Nakamura       | coding    | new applet      |
| /usr/sbin/restorecond |                |           | no plan         |
| /usr/sbin/run\_init | Nakamura       | ready     | new applet      |
| /usr/sbin/semanage |                |           | depend on libsemanage |
| /usr/sbin/semodule |                |           | depend on libsemanage |
| /usr/sbin/sestatus | KaiGai         | ready     | new applet      |
| /usr/sbin/setsebool | Shinji         | ready     | new applet      |

### libselinux package ###
| **command** | **assignment** | **state** | **description** |
|:------------|:---------------|:----------|:----------------|
| /usr/sbin/avcstat | KaiGai         | discard   | new applet      |
| /usr/sbin/getenforce | Shinji         | **merged** | new applet      |
| /usr/sbin/getsebool | Shinji         | **merged** | new applet      |
| /usr/sbin/matchpathcon | KaiGai         | **merged** | new applet      |
| /usr/sbin/selinuxenabled | Shinji         | **merged** | new applet      |
| /usr/sbin/setenforce | Shinji         | **merged** | new applet      |
| /usr/sbin/togglesebool | Shinji         | discard   | new applet      |

### findutils package ###
| **command** | **assignment** | **state** | **description** |
|:------------|:---------------|:----------|:----------------|
| /usr/bin/find | KaiGai         | **merged** | -context rule support |

### net-tools package ###
| **command** | **assignment** | **state** | **description** |
|:------------|:---------------|:----------|:----------------|
| /bin/netstat | KaiGai         | ready     | -Z option support (limited to named UNIX socket) |