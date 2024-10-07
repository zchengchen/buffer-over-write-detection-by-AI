# GPT-4o for vulnerability detection, PoV and patches Generation
## Build
You should build CP before running py scripts.
```Bash
cd nginx-cp
make cpsrc-prepare
make docker-pull
./run build
```
If build fails, please check this repo for more information: https://github.com/aixcc-public/challenge-004-nginx-cp.

## How to use it
You could run this command to detect the potential Out-of-Bounds Write, and result would be stored in `analysis_result.json`.
```Bash
python3 gpt_for_vuln_detect.py
```

## Result for finding CPV1 (induced by Commit 165)

