# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import json
import logging


def output_to_csv(alerts_per_repos: Dict, location: str) -> bool:
    try:
        with open(location, "w") as log_file:
            log_file.write(json.dumps(alerts_per_repos))
    except Exception as e:
        logging.error(str(e))
        logging.error(f"Failure to write the output to {location}")
        return False
    return True
