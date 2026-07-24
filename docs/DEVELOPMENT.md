## Development

```bash
# Run tests
pytest

# Linting and formatting
ruff check .
black .
mypy decbench
```

## Architecture

```
decbench/
  pipeline/         # compile -> decompile -> evaluate orchestration
  metrics/          # ged.py, type_match.py, byte_match.py, fixup.py
  decompilers/      # raw angr/ghidra/ida/binja + dewolf, dockerized, LLM agents
  compilers/        # gcc plugin
  models/           # Pydantic data models
  scoring/          # aggregation, scoreboard, datasets, report extras
  rendering/        # the report + the deployable site
    html.py         #   skeleton assembly only — no CSS, no JS, no prose
    aggregate.py    #   build-time aggregation -> the site's JSON payloads
    site.py         #   the split GitHub Pages tree (decbench site build)
    content.py      #   loader for content/
    content/        #   ALL editable text: *.md per view + site/views/metrics/
                    #   datasets/decompilers/categories .toml
    assets/         #   app.css, app.js, vendored font
  utils/            # binfmt.py, source_extract.py, cfg.py
  cli.py            # Click-based CLI
scripts/            # scalable run drivers + offline metric re-eval/rebuild
site/               # the built Pages tree, committed (see "Rendering the site")
docs/               # ADDING_A_DECOMPILER.md, DATASET_PUBLISHING.md,
                    # LLM_DECOMPILERS.md, SITE_DATA_SCHEMA.md
```