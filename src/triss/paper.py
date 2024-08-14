# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import itertools
import math
from pathlib import Path
import sys

try:
    from PIL import Image
except ModuleNotFoundError:
    pass

from triss import image, util


def batched(iterable, n):
    # batched('ABCDEFG', 3) → ABC DEF G
    # Added to itertools in python 3.12
    if n < 1:
        raise ValueError('n must be at least one')
    iterator = iter(iterable)
    while batch := tuple(itertools.islice(iterator, n)):
        yield batch


MODE = 'RGBA'


def n_up(n, in_paths, out_path):
    """
    Merge images at IN_PATHS in tiling fashion, up to N images per output.

    Output images are written to files named like OUT_PATH.$PAGE_NUMBER.png
    """
    image.ensure_pil(what_for="Triss 'paper' utilities require")
    in_paths = list(in_paths)
    n_pages = util.div_up(len(in_paths), n)
    pg_no_width = int(math.log10(n_pages)) + 1
    out_path = Path(out_path)
    if out_path.suffix != ".png":
        out_path = out_path.with_suffix(".png")

    pg_no = 1
    for grid in batched(in_paths, n):
        page = Image.new(MODE, (0, 0), 'white')
        gw = math.ceil(math.sqrt(len(grid)))  # max number of images per stripe
        for row in batched(grid, gw):
            stripe = Image.new(MODE, (0, 0), 'white')
            for im in [Image.open(f) for f in row]:
                stripe = image.merge_x(stripe, im)
            page = image.merge_y(page, stripe)
        page_path = out_path.with_suffix(
            f".pg-{pg_no:0{pg_no_width}}-of-{n_pages}.png")
        print(f"Writing {page_path}", file=sys.stderr)
        page.save(page_path)
        pg_no += 1


if __name__ == '__main__':
    import sys
    n_up(int(sys.argv[1]), sys.argv[2:-1], sys.argv[-1])
