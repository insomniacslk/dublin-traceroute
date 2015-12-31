import sys

from distutils.core import setup, Extension


if sys.version_info.major >= 3:
    sources = ['dublintraceroute/py3/_dublintraceroute.cc']
else:
    sources = ['dublintraceroute/py2/_dublintraceroute.cc']


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
    sources=sources,
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
