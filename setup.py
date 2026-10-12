"""Bundle canonical root schemas into the wheel without source duplication."""
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def run(self):
        super().run()
        destination = Path(self.build_lib) / 'acve' / 'schemas'
        destination.mkdir(parents=True, exist_ok=True)
        for source in sorted((Path(__file__).parent / 'schemas').glob('*.schema.json')):
            self.copy_file(str(source), str(destination / source.name))

    def get_outputs(self, include_bytecode=True):
        outputs = super().get_outputs(include_bytecode)
        outputs.extend(str(Path(self.build_lib) / 'acve' / 'schemas' / source.name)
                       for source in sorted((Path(__file__).parent / 'schemas').glob('*.schema.json')))
        return outputs


setup(cmdclass={'build_py': BuildPy})
