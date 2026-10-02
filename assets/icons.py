#!/usr/bin/env python3
"""Draw the application icons and write them as multi-size .ico files.

Run from the repository root with Pillow installed:

    python3 assets/icons.py

Outputs:
    crates/mw/assets/mw.ico             embedded in mw.exe
    crates/netshell/assets/netshell.ico embedded in netshell.exe
    assets/mw.png, assets/netshell.png  256 px previews for the README
"""

from PIL import Image, ImageDraw, ImageFont

SIZE = 256
RADIUS = 56
SIZES = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)]

NAVY = (15, 23, 42, 255)        # background
WHITE = (248, 250, 252, 255)
BEFORE = (148, 163, 184, 255)   # slate: the state before the change
AFTER = (45, 212, 191, 255)     # teal: the state after
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def canvas():
    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((0, 0, SIZE - 1, SIZE - 1), radius=RADIUS, fill=NAVY)
    return image, draw


def centered_text(draw, text, font, cy, fill):
    left, top, right, bottom = draw.textbbox((0, 0), text, font=font)
    width, height = right - left, bottom - top
    draw.text(((SIZE - width) / 2 - left, cy - height / 2 - top), text, font=font, fill=fill)


def mw():
    """'mw' in white; under it a bar whose left half is the before colour
    and right half the after colour: the two captures the tool compares."""
    image, draw = canvas()
    centered_text(draw, "mw", ImageFont.truetype(FONT, 118), 112, WHITE)
    y0, y1 = 186, 206
    draw.rounded_rectangle((44, y0, 128, y1), radius=10, fill=BEFORE)
    draw.rounded_rectangle((128, y0, 212, y1), radius=10, fill=AFTER)
    return image


def netshell():
    """A shell prompt in the after colour: the driver's whole job."""
    image, draw = canvas()
    font = ImageFont.truetype(FONT, 132)
    left, top, right, bottom = draw.textbbox((0, 0), ">_", font=font)
    draw.text(((SIZE - (right - left)) / 2 - left, 128 - (bottom - top) / 2 - top - 8), ">_", font=font, fill=AFTER)
    return image


def write(image, ico_path, png_path):
    image.save(png_path)
    image.save(ico_path, sizes=SIZES)


if __name__ == "__main__":
    write(mw(), "crates/mw/assets/mw.ico", "assets/mw.png")
    write(netshell(), "crates/netshell/assets/netshell.ico", "assets/netshell.png")
    print("wrote crates/mw/assets/mw.ico and crates/netshell/assets/netshell.ico")
