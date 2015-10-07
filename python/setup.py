from distutils.core import setup, Extension

dublintraceroute = Extension(
    'dublintraceroute._dublintraceroute',
    language='c++',
    libraries=['dublintraceroute', 'tins'],
    include_dirs=[
        '../include',
        '../dependencies/libtins/include',
        '../dependencies/g3log/src',
        '../dependencies/jsoncpp/dist',
    ],
    sources=['dublintraceroute/_dublintraceroute.cc'],
    extra_compile_args=[
        '-std=c++11',
        '-ldublintraceroute',
    ],
    extra_link_args=[],
)


setup(
    name='DublinTraceroute',
    version='1.0',
    author='Andrea Barberio',
    author_email='<insomniac@slackware.it>',
    description='NAT-aware multipath traceroute',
    url='https://www.dublin-traceroute.net',
    packages=['dublintraceroute'],
    ext_modules=[dublintraceroute],
)
