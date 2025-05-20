#!/bin/bash

[ "$1" == "--pcaps" ] && rm -f pcaps/* && echo "pcaps очищена"
[ "$1" == "--parsed" ] && rm -f parsed/* && echo "parsed очищена"
[ "$1" == "--all" ] && rm -f pcaps/* parsed/* && echo "Очищены pcaps и parsed"
