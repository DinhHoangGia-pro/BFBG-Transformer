"""
path_resolver.py
================
Doc configs/*.yaml va giai duong dan tuong doi theo GOC REPO - thay cho
bien moi truong HIN_DIR_DEFI va duong dan tuyet doi hardcode cua ban EVM.

    from src.utils.path_resolver import load_config, get_path
    cfg = load_config('model')                 # configs/model.yaml
    features_dir = get_path('features_dir')    # paths.features_dir trong config.yaml, da resolve
"""

import functools
import os

import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
CONFIG_DIR = os.path.join(REPO_ROOT, 'configs')


def resolve(path):
    """Duong dan tuong doi -> tuyet doi tinh tu goc repo; tuyet doi giu nguyen."""
    path = os.path.expanduser(path)
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(REPO_ROOT, path))


@functools.lru_cache(maxsize=None)
def load_config(name):
    """Doc configs/<name>.yaml (name: 'config', 'dataset', 'model')."""
    with open(os.path.join(CONFIG_DIR, f'{name}.yaml')) as f:
        return yaml.safe_load(f) or {}


def get_path(key):
    """paths.<key> trong configs/config.yaml, da resolve theo goc repo."""
    paths = load_config('config').get('paths', {})
    if key not in paths:
        raise KeyError(f"configs/config.yaml khong co paths.{key}")
    return resolve(paths[key])


def get_seed():
    return load_config('config')['seed']
