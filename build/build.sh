#!/bin/bash

RootPath=$(cd $(dirname $0)/..; pwd)
BuildPath=${RootPath}/build
BuildOutPath=${BuildPath}/out
BuildBinPath=${BuildPath}/bin
VendorPath=${RootPath}/vendor

BranchName=$(git rev-parse --abbrev-ref HEAD)
CommitID=$(git rev-parse HEAD)
BuildTime=$(date +%Y-%m-%d\ %H:%M)
LDFlags="-X main.CommitID=${CommitID} -X main.BranchName=${BranchName} -X 'main.BuildTime=${BuildTime}'"
MODFLAGS=""

RM="rm -rf"
[[ -x "/usr/bin/rm" ]] && RM="/usr/bin/rm -rf"
[[ -x "/bin/rm" ]] && RM="/bin/rm -rf"

NPROC=$(nproc 2>/dev/null)
NPROC=${NPROC:-"1"}

GCC_LIBRARY_PATH="/lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64"

[[ $(uname -s) != "Linux" ]] && { echo "ChubaoFS only support Linux os"; exit 1; }

TMPDIR=${HOME}/tmp/$$
mkdir -p ${TMPDIR}

set_go_path() {
    export GOPATH=${TMPDIR}
    mkdir -p $GOPATH/src/github.com/chubaofs
    SrcPath=$GOPATH/src/github.com/chubaofs/chubaofs
    if [[  ! -e "$SrcPath" ]] ; then
        ln -s $RootPath $SrcPath 2>/dev/null
    fi
}

build_snappy() {
    SnappySrcPath=${RocksdbBuildPath}/third-party/snappy-1.1.7
    SnappyBuildPath=${SnappySrcPath}/build
    found=$(find ${SnappyBuildPath} -name libsnappy.a 2>/dev/null | wc -l)
    if [[ ${found} -eq 0 ]] ; then
        if [[ ! -d ${RocksdbBuildPath} ]] ; then
            mkdir -p ${RocksdbBuildPath}
            cp -rf ${RocksdbSrcPath}/* ${RocksdbBuildPath}
        fi
        mkdir -p ${SnappyBuildPath}
        echo "build snappy..."
        pushd ${SnappyBuildPath} >/dev/null
        cmake ${SnappySrcPath} && make -j ${NPROC}  && echo "build snappy success" || {  echo "build snappy failed"; exit 1; }
        popd >/dev/null
    fi
    cgo_cflags="${cgo_cflags} -I${SnappySrcPath}"
    cgo_ldflags="${cgo_ldflags} -L${SnappyBuildPath} -lsnappy"
}

build_rocksdb() {
    RocksdbSrcPath=${VendorPath}/rocksdb-5.9.2
    RocksdbBuildPath=${BuildOutPath}/rocksdb

    build_snappy

    found=$(find ${RocksdbBuildPath} -name librocksdb.a 2>/dev/null | wc -l)
    if [[ ${found} -eq 0 ]] ; then
        if [[ ! -d ${RocksdbBuildPath} ]] ; then
            mkdir -p ${RocksdbBuildPath}
            cp -rf ${RocksdbSrcPath}/* ${RocksdbBuildPath}
        fi
        echo "build rocksdb..."
        pushd ${RocksdbBuildPath} >/dev/null
        [[ "-$LUA_PATH" != "-" ]]  && unset LUA_PATH
        make -j ${NPROC} static_lib  && echo "build rocksdb success" || {  echo "build rocksdb failed" ; exit 1; }
        popd >/dev/null
    fi
    cgo_cflags="${cgo_cflags} -I${RocksdbSrcPath}/include"
    cgo_ldflags="${cgo_ldflags} -L${RocksdbBuildPath} -lrocksdb"
}

set_server_deps() {
    cgo_cflags=""
    cgo_ldflags=""

    build_rocksdb

    export CGO_CFLAGS=${cgo_cflags}
    export CGO_LDFLAGS="${cgo_ldflags}"
    export GO111MODULE=off
}

run_test() {
    set_go_path
    set_server_deps
    pushd $SrcPath >/dev/null
    echo "run test "
    go test -ldflags "${LDFlags}" ./...
    popd >/dev/null
}

build_server() {
    set_go_path
    set_server_deps
    pushd $SrcPath >/dev/null
    echo -n "build cfs-server "
    go build $MODFLAGS -ldflags "${LDFlags}" -o ${BuildBinPath}/cfs-server ${SrcPath}/cmd/*.go && echo "success" || echo "failed"
    popd >/dev/null
    unset CGO_LDFLAGS CGO_CFLAGS
}

build_client() {
    set_go_path
    pushd $SrcPath >/dev/null
    echo -n "build cfs-client "
    go build $MODFLAGS -ldflags "${LDFlags}" -o ${BuildBinPath}/cfs-client ${SrcPath}/client/*.go  && echo "success" || echo "failed"
    popd >/dev/null
}

build_client2() {
    set_go_path
    pushd $SrcPath >/dev/null
    echo -n "build cfs-client2 "
    go build $MODFLAGS -ldflags "${LDFlags}" -o ${BuildBinPath}/cfs-client2 ${SrcPath}/clientv2/*.go  && echo "success" || echo "failed"
    popd >/dev/null
}

build_authtool() {
    set_go_path
    pushd $SrcPath >/dev/null
    echo -n "build cfs-authtool "
    go build $MODFLAGS -ldflags "${LDFlags}" -o ${BuildBinPath}/cfs-authtool ${SrcPath}/authtool/*.go  && echo "success" || echo "failed"
    popd >/dev/null
}

clean() {
    ${RM} ${BuildBinPath}
}

dist_clean() {
    ${RM} ${BuildBinPath}
    ${RM} ${BuildOutPath}
}

cmd=${1:-"all"}

case "$cmd" in
    "all")
        build_server
        build_client
        ;;
    "test")
        run_test
        ;;
    "server")
        build_server
        ;;
    "client")
        build_client
        ;;
    "client2")
        build_client2
        ;;
    "authtool")
        build_authtool
        ;;
    "clean")
        clean
        ;;
    "dist_clean")
        dist_clean
        ;;
    *)
        ;;
esac

${RM} ${TMPDIR}
