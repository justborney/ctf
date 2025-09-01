#!/bin/sh

while [ true ]; do
	socat TCP-LISTEN:2200,fork,reuseaddr EXEC:'./chall'
done;