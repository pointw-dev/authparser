import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
      name='authparser',
      version='1.0',
      author='Michael Ottoson',
      author_email='michael@pointw.com',
      description="Used to parse http Authentication headers, and to call handlers per scheme.",
      long_description=long_description,
      long_description_content_type="text/markdown",
      url='https://github.com/pointw-dev/authparser',
      packages=setuptools.find_packages(),
      license='MIT',
      install_requires=[
          'pyparsing'
      ],
      classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
      ])
