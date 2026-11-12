"""Idempotent local retirement migration. Never touch state, reports or targets.

Run only after a successful update, or on the next no-change update. Old
updaters first install the closed registries; a second update removes files.
"""
from pathlib import Path
import os

RETIRED_FILES = (
    'scripts/12-credential-access.sh', 'scripts/13-native-tools.sh',
    'scripts/14-c2.sh', 'scripts/15-web-app.sh',
    'scripts/16-defense-evasion.sh', 'scripts/17-collection.sh',
    'scripts/18-dns.sh', 'web/collection_state.py', 'web/dns_actions.py',
    'web/exercise_actions.py', 'web/lab_actions.py', 'web/native_actions.py',
    'web/web_lab.py', 'web/web_profiles.py',
)


def migrate(base):
    base = Path(base).resolve(strict=True)
    removed = []
    for relative in RETIRED_FILES:
        path = base / relative
        # Reject symlinked code directories; do not follow paths outside install.
        if path.parent.is_symlink() or path.parent.resolve() != base / path.parent.name:
            raise ValueError('Unsafe retired code directory: ' + path.parent.name)
        candidates = [path, path.with_suffix('.pyc')] if path.suffix == '.py' else [path]
        cache = path.parent / '__pycache__'
        if path.suffix == '.py' and cache.is_dir() and not cache.is_symlink():
            candidates.extend(cache.glob(path.stem + '.*.pyc'))
        for candidate in candidates:
            if candidate.is_symlink() or candidate.is_file():
                candidate.unlink()
                removed.append(candidate.relative_to(base).as_posix())
    return removed


if __name__ == '__main__':
    for relative in migrate(os.environ.get('NORDIC_BASE_DIR', '/opt/nordic-attack')):
        print('RETIRED  ' + relative)
