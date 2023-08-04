#!/bin/bash

if [[ $# -eq 0 ]] ; then
    echo 'You need to supply a version bump argument: patch, minor, or major'
    exit 1
fi

# list of directories to bump versions
directories=("e2ee-appkit-browser" "e2ee-appkit-node" "e2ee-appkit-shared-models")

# root directory where the packages are located
root_directory="packages"

for dir in "${directories[@]}"
do
  # check if directory exists
  if [ -d "$root_directory/$dir" ]; then
    echo "Updating $1 version for package: $dir"
    cd "$root_directory/$dir"
    npm version $1
    cd ../..
  else
    echo "Directory $root_directory/$dir does not exist, skipping"
  fi
done