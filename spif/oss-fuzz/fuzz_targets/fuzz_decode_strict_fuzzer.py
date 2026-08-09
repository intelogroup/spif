import atheris
import sys

with atheris.instrument_imports():
    import spif


@atheris.instrument_func
def TestOneInput(data):
    try:
        spif.SPIFReader.strict().decode(data)
    except spif.SPIFError:
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
