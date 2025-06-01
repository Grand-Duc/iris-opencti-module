import setuptools


setuptools.setup(
     name='iris_opencti_module',
     version='1.0.1',
     packages=['iris_opencti_module', 'iris_opencti_module.opencti_handler'],
     author="Grand-Duc",
     author_email="xx@xx",
     description="An Iris Module that linked to OpenCTI to share IOCs",
     long_description="An Iris Module that linked to OpenCTI to share IOCs",
     long_description_content_type="text/markdown",
     url="https://github.com/",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: LGPLv3",
         "Operating System :: OS Independent",
     ],
 )