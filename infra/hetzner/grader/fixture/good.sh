#!/bin/sh
read -r first second
printf '%s\n' "$((first + second))"
