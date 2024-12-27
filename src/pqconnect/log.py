import logging
import sys

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

sh = logging.StreamHandler(sys.stderr)
sh.setFormatter(formatter)
logger.addHandler(sh)
