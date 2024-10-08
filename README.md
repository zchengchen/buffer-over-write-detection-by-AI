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
### Run it for specific commit and function
You could run this command to detect the potential Out-of-Bounds Write, and result would be stored in `analysis_result.json`.
```Bash
python3 gpt_for_vuln_detect.py
```
If you already have `analysis_result.json`, you could skip the command above, and run following command to generate payload (or blob). The payload would be stored in `vuln_cpv1.bin`.
```Bash
python3 gpt_for_payload.py --commit_index 165 --func ngx_http_validate_from
```
To genreate patch for a specific function , you could run following command. The diff file would be stored in `bad_patch.diff` or `good_patch.diff`.
```Bash
python3 gpt_for_patch.py --commit_index 165 --func ngx_http_validate_from
```
### Run it for all commits and all suspicious functions.


## Result for finding CPV1 (induced by Commit 165)

