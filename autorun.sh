#!/bin/bash

bash ./cleaning.sh
bash ./gpars.sh

[ "$1" == "--neuro" ] && python3 ./core/neuro.py
[ "$1" == "--destree" ] && python3 ./core/destree.py