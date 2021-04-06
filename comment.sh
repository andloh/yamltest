#!/bin/bash

# Override
files=`find * -name *.yaml | grep -v "__init__"`

for file in $files; do sed -i "1i # THIS FILE IS MANAGED BY GITOPS - https://github.com/domstolene/k8s-applications/tree/${GITHUB_BASE_REF}/$file" $file; done
