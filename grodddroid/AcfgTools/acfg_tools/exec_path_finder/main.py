#!/usr/bin/env python3
""" Find execution paths to targets from an ACFG. """

import argparse
import logging
import os.path

from acfg_tools.exec_path_finder.acfg import AppGraph
from acfg_tools.exec_path_finder.path_finder import PathFinder
from acfg_tools.exec_path_finder.targets import generate_target_list
from acfg_tools.exec_path_finder.path_alert import get_path_info_for_alert

DESCRIPTION = "Execution path finder"

# Setup logging
log = logging.getLogger("acfgtools")


def main():
    argparser = argparse.ArgumentParser(description=DESCRIPTION)
    argparser.add_argument("acfg", type=str, help="Application CFG")
    argparser.add_argument("targets", type=str, help="targets JSON list")
    args = argparser.parse_args()

    if not os.path.isfile(args.acfg) or not os.path.isfile(args.targets):
        print("Unavailable file or directory given.")
        return

    log.info("Importing the first alert of the first target.")

    app_graph = AppGraph()
    app_graph.load_dot(args.acfg)

    target_list = generate_target_list(args.targets)
    alert = target_list[0].alerts[0]

    # TODO: update args list
    get_path_info_for_alert(app_graph, alert, False)


if __name__ == "__main__":
    main()
