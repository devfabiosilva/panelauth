from distutils.core import setup, Extension, os

def main():
    setup(name="panelauth",
        version="0.1.0",
        description="PLC panel / IoT AUTH2 and HMAC protocol modules for Python 3 using C library setup",
        author="Fábio Pereira da Silva",
        author_email="fabioegel@gmail.com",
        maintainer_email="fabioegel@gmail.com",
        ext_modules=[Extension("panelauth", ["module.c"],
            library_dirs=['lib'],
            libraries=['mbedtls'],
            extra_objects=['cauth.o', 'cyodecode.o'],
            include_dirs=['include', 'include/mbedtls', 'include/cyoencode'],
            define_macros=[('P_DEBUG', None)]
        )])

if __name__ == "__main__":
    main()
