#!/bin/bash

cargo build

sudo setcap cap_net_admin=eip target/debug/server

./target/debug/server