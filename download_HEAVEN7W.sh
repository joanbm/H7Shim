#!/usr/bin/env bash
set -euo pipefail
curl -L "https://files.scene.org/get/parties/2000/mekkasymposium00/in64/h7-final.zip" > /tmp/h7-final.zip
# shellcheck disable=SC2094
unzip -p /tmp/h7-final.zip HEAVEN7W.EXE > HEAVEN7W.EXE
echo "3171d7bbe7faf70d5f3a6f6e24292e33a5007316156734a63b42cdf2f8805453  HEAVEN7W.EXE" | sha256sum -c
