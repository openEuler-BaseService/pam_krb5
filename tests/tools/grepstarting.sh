#!/bin/sh
exec grep -q starting "$*" 2> /dev/null
