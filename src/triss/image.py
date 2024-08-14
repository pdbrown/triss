# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
PIL (Python Image Library) utilities and helpers.
"""


try:
    from PIL import Image, ImageDraw, ImageFont
    HAVE_PIL = True
except ModuleNotFoundError:
    HAVE_PIL = False


TRY_FONTS = ["Helvetica.ttf", "DejaVuSans.ttf", "Arial.ttf"]


def ensure_pil(what_for="Triss requires"):
    if not HAVE_PIL:
        raise RuntimeError(
            f"Error: {what_for} the Python Image Library "
            "(PIL) as provided by the pillow dist package, but it is not "
            "available.\n"
            "Try reinstalling triss:   pip install --upgrade triss\n"
            "or try installing pillow: pip install pillow")


def load(path):
    # Read image data into img, then close img_path keeping img in memory.
    with Image.open(path) as img:
        img.load()
    return img


def merge_x(im_left, im_right):
    w = im_left.size[0] + im_right.size[0]
    h = max(im_left.size[1], im_right.size[1])
    im = Image.new('RGBA', (w, h), 'white')
    im.paste(im_left)
    im.paste(im_right, (im_left.size[0], 0))
    return im


def merge_y(im_top, im_bottom):
    w = max(im_top.size[0], im_bottom.size[0])
    h = im_top.size[1] + im_bottom.size[1]
    im = Image.new('RGBA', (w, h), 'white')
    im.paste(im_top)
    im.paste(im_bottom, (0, im_top.size[1]))
    return im


def pad_vertical(img):
    w, h = img.size
    if w <= h:
        return img
    out = Image.new('RGBA', (w, w + 1), 'white')
    out.paste(img)
    return out


def find_font(size):
    size = int(size)
    for font in TRY_FONTS:
        try:
            return ImageFont.truetype(font, size)
        except Exception:
            pass
    return None


def font_height(font, text, spacing=4):
    img = Image.new("RGBA", (1, 1))
    d = ImageDraw.Draw(img)
    (left, top, right, bottom) = d.multiline_textbbox(
        (0, 0), text, font=font, spacing=spacing)
    return bottom - top


def add_xy(pos, dxdy):
    x, y = pos
    dx, dy = dxdy
    return (x + dx, y + dy)
