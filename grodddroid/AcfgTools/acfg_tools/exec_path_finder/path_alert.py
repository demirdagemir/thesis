import logging

from acfg_tools.exec_path_finder.path_finder import PathFinder


def get_path_info_for_alert(app_graph, alert, exhaustive_paths, paths_out,
                            alert_types, log_level=logging.DEBUG):
    log.setLevel(log_level)
    path_finder = PathFinder(app_graph, exhaustive_paths, paths_out)
    path_info = path_finder.process_alert(alert, alert_types)
    return path_info