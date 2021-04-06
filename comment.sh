#!/bin/bash

# Find Files
files=`find * -name *.yaml | grep -v "__init__"`

# Comment
comment="# THIS FILE IS MANAGED BY GITOPS - https://github.com/domstolene/k8s-applications/tree/${GITHUB_BASE_REF}"

for file in $files; do grep -q "$comment/$file" $file || sed -i "1i $comment/$file" $file; done
