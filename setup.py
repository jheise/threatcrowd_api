from distutils.core import setup

setup( name="threatcrowd",
       version='0.4',
       py_modules=['threatcrowd'],
       requires=['requests(>=2.4.0)'],
       install_requires=['requests>=2.4.0'],
       url="https://github.com/jheise/threatcrowd_api",
       author="Jon Heise",
       author_email="j.heise@gmail.com",
       description="library for working with the threatcrowd api."

)
