#!/usr/bin/env bash

version=$(git describe --exact-match HEAD 2>/dev/null)

if [[ -z "$version" ]]; then
    tag_hash=$(git rev-list --tags --max-count=1)
    previous_version=$(git describe --tags "${tag_hash}")
    git_hash=$(git rev-parse --verify --short HEAD)
    # shellcheck disable=2206
    a=( ${previous_version//./ } )
    ((a[2]++))
    version="${a[0]}.${a[1]}.${a[2]}-dev+sha.${git_hash}"
fi

echo "$version"
