#!/bin/bash

# Assuming node is installed with nvm, we need to set up the environment
# variables and set the PATH to be able to run node
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

cd /home/ubuntu/formatvideo
node backend/worker.js
