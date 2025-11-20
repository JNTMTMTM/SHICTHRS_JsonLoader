from setuptools import setup, find_packages

setup(name='SHICTHRSJsonLoader',
      version='1.2.0',
      description='SHICTHRS json file io/encrypt-decrypt system',
      url='https://github.com/JNTMTMTM/SHICTHRS_LogCore',
      author='SHICTHRS',
      author_email='contact@shicthrs.com',
      license='GPL-3.0',
      packages=find_packages(),
      include_package_data=True,
      install_requires=['colorama==0.4.6' , 'pycryptodome==3.23.0'],
      zip_safe=False)
