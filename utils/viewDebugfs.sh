#!/bin/bash
# required root to run
watch -td -n 1 "awk 'FNR==1{print ""FILENAME""} {print}' /sys/kernel/debug/ycache/*"