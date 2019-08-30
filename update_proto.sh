#!/usr/bin/env bash
cd $(dirname $0)
set -x

UNITY_PROJECT_PATH=$1
if [ ! -d "${UNITY_PROJECT_PATH}" ]
then
    exit 1
fi

rsync -av --exclude='/.svn' --delete ${UNITY_PROJECT_PATH}/BuildProto/Protocol/ ./__proto
rsync -av ${UNITY_PROJECT_PATH}/BuildDataConfig/step1_xls2proto/xls_enum.proto ./__proto