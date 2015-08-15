import sys
import msilib
from cx_Freeze import setup, Executable

product_name = "Data Syncer"
base = None
includes = ['lxml.etree', 'lxml._elementpath', 'inspect']

icon_table = [
    ('appicon', msilib.Binary('icon.ico'))
]

property_table = [
    ('ARPPRODUCTICON', 'appicon')
]

msi_data = {
    'Icon': icon_table,
    'Property': property_table
}

bdist_msi_options = {
    'add_to_path': True,
    'initial_target_dir': r'[ProgramFilesFolder]\%s' % (product_name),
    'upgrade_code':'{db917877-b523-4795-a188-4e579d35b468}', # http://www.guidgen.com/
    'data': msi_data
}

build_exe_options = {
    'includes': includes
}

setup(  name = "Data Syncer",
        version = "0.5.1",
        author = "Nick D'Ademo",
        author_email = "nickdademo@gmail.com",
        description = "Data Syncer",
        data_files = [
                ('', ['data-syncer_config_SAMPLE.xml', 'data-syncer_config.xsd', 'README.txt'])
            ],
        executables = [Executable("data-syncer.py", base=base, targetName="data-syncer.exe", icon="icon.ico")],
        options = {
            'bdist_msi': bdist_msi_options,
            'build_exe': build_exe_options
            }
        )