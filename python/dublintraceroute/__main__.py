from __future__ import print_function

import json

from dublintraceroute import DublinTraceroute, print_results, to_graphviz


def parse_args():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--plot',
                        type=argparse.FileType('r'),
                        help='Read a JSON file and plot it')
    parser.add_argument('target',
                        nargs='?',
                        help='The target to traceroute')
    args = parser.parse_args()
    if args.target and args.plot:
        raise parser.error('--plot and target are mutually exclusive')
    return args


def main():
    args = parse_args()
    if args.target:
        dub = DublinTraceroute(args.target)
        results = dub.traceroute()
        print_results(results)
    elif args.plot:
        results = json.load(args.plot)
        graph = to_graphviz(results)
        graph.layout('dot')
        outfile = args.plot.name + '.png'
        graph.draw(outfile)
        print('Saved to {o}'.format(o=outfile))
    else:
        print('No action requested. Try --help')

main()
