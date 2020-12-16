#!/bin/bash
set -eou pipefail
cd $(dirname $0)
if ! docker inspect arch:bpftrace &>/dev/null; then
    id=$(cat /proc/sys/kernel/random/uuid)
    if docker run --name $id -it --network host archlinux:latest bash -c "pacman -Sy --noconfirm which make git gcc go bpftrace python-bcc"; then
        docker commit $id arch:bpftrace
    fi
fi
kernel=$(uname -r)
# opts="--privileged -v /usr/lib/modules/$kernel:/usr/lib/modules/$kernel:ro"
# opts="--privileged -v /usr/lib/modules/$kernel:/usr/lib/modules/$kernel:ro -v /sys/kernel/debug:/sys/kernel/debug:ro --cap-add=SYS_ADMIN --security-opt no-new-privileges"
opts="--privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro -v /usr/lib/modules/$kernel:/usr/lib/modules/$kernel:ro -v /sys/kernel/debug:/sys/kernel/debug:ro --cap-add=SYS_ADMIN --security-opt no-new-privileges"
if [ -z "$1" ]; then
    docker run $opts -it --network host --workdir /code -v $(pwd)/scripts:/code:ro --rm arch:bpftrace bash
else
    docker run $opts -it --network host --workdir /code -v $(pwd)/scripts:/code:ro --rm arch:bpftrace "$@"
fi
