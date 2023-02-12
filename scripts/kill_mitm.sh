#!/bin/bash
kill -9 `ps aux | grep [m]itmdump | awk '{print $2}' | xargs`