C++ library and CLI: [![Build Status](https://www.travis-ci.org/insomniacslk/dublin-traceroute.svg?branch=master)](https://www.travis-ci.org/insomniacslk/dublin-traceroute)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/7935/badge.svg)](https://scan.coverity.com/projects/insomniacslk-dublin-traceroute)

Python module: [![Build Status](https://www.travis-ci.org/insomniacslk/python-dublin-traceroute.svg?branch=master)](https://www.travis-ci.org/insomniacslk/python-dublin-traceroute) [![Version](https://img.shields.io/pypi/v/dublintraceroute.svg)](https://pypi.python.org/pypi/dublintraceroute)

Debian packages:

![Debian Unstable](https://badges.debian.net/badges/debian/unstable/dublin-traceroute/version.svg)
![Debian Testing](https://badges.debian.net/badges/debian/testing/dublin-traceroute/version.svg)

Dublin Traceroute is a NAT-aware multipath traceroute tool.

And this page is just informational. **Read more at https://dublin-traceroute.net** .

Dublin Traceroute has a blog, with articles on how to make the best out of it. Check it out at https://blog.dublin-traceroute.net .

Dublin Traceroute has also Python bindings, that will let you:
* use Dublin Traceroute from Python code
* generate graphical visualizations of your multipath traceroutes
* do statistical analysis using Pandas

See [python-dublin-traceroute](https://github.com/insomniacslk/python-dublin-traceroute) for more information.

Feedback is very welcome! You can [open a new issue](https://github.com/insomniacslk/dublin-traceroute/issues/new/choose), or contact me directly, see https://insomniac.slackware.it for contact details.

But, in a few words, you can run traceroutes in multi-path networks (i.e. with ECMP load-balancing enabled), recognize NATs, have nice diagrams like the one below, export to JSON, and do this with a command-line tool, a C++ library or a Python library.

![dublin-traceroute example](docs/traceroute_8.8.8.8.png)
