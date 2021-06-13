# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from __future__ import annotations

import configparser
import os
from pathlib import Path


class Config:
    def __init__(self, config_file: Path = None):
        if config_file is None:
            config_file = Path.home() / '.ksf' / 'config.ini'
            if not config_file.exists():
                # todo replace with confirmation
                print(f"Config file {config_file} not found. Creating default.")
                self._create_default(config_file)
        self.config_file = config_file

        config = configparser.ConfigParser()
        config.read(str(config_file))

        data_path_str = config['main']['dir']

        data_path_str = os.path.expanduser(data_path_str)
        data_path_str = os.path.expandvars(data_path_str)
        #print(data_path_str)
        self.data_dir = Path(data_path_str)
        #print(self.data_dir)
        if not self.data_dir.is_absolute():
            self.data_dir = (config_file.parent / self.data_dir).resolve()
        #print(self.data_dir)

    @staticmethod
    def _create_default(config_file: Path):
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config = configparser.ConfigParser()

        relative_data_path = './data'
        config['main'] = {'dir': relative_data_path}
        (config_file.parent / relative_data_path).mkdir()
        with config_file.open('w') as f:
            config.write(f)
