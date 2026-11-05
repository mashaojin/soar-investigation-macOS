# Repository and publication

## Included

Current runtime modules and their shared dependencies, dashboard assets, synthetic regression fixtures, offline tests, configuration examples, current documentation, exported instructions and the example SSH sensor rule. Python sources remain at the root so current sibling-file imports and victim-side script loading work without changing runtime paths.

## Local only

The active `*.local.json` files, `rule-editor-enabled.json`, actual test-plan registry, SQLite databases, lock files, credentials and generated artifacts stay local and are ignored. `configure_local.py` provides reproducible private defaults for a fresh checkout. Local initialization preserves existing live-mode configuration rather than silently changing a running lab.

## Archived separately

A sibling `soc-pipeline-archive-<UTC timestamp>` directory contains old development backups, receipts, screenshots, retired scripts/tests, previous documentation, inactive configuration/databases and Word-plan history. Nothing was deleted. The archive manifest preserves source/destination paths and moves were verified by SHA-256. A consistent snapshot of active state was also saved before cleanup. The archive contains private data and is not part of the public repository.

## Before publishing

1. Run the offline tests and JavaScript syntax checks from README.
2. Review `git status --short` and the files selected for publication. Never force-add ignored local files.
3. Confirm no bot tokens, private keys, actual approvals or incident databases are included.
4. Choose your own repository visibility, license and GitHub destination. No license grant is inferred from this cleanup.

A release export must follow Git's included-file list rather than copying the whole live folder. Generated release checks and historical archives remain outside the public source tree. No GitHub repository creation, commit or push is performed by the local organization step.
