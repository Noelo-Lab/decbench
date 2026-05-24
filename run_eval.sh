docker run \
  -v $(pwd)/results:/workspace/results \
  -v $(pwd)/decbench:/workspace/decbench \
  -v $(pwd)/e2e_coreutils_eval.py:/workspace/e2e_coreutils_eval.py \
  decbench:latest \
  python3 e2e_coreutils_eval.py --output /workspace/results --skip-compile --sample 2