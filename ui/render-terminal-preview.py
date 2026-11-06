#!/usr/bin/env python3
"""Development-only raster rendering of the actual sample terminal text.

This is not a browser screenshot or a live diagnostic result. Pillow is only
used on the build machine; the shipped UI has no third-party dependencies.
"""
import importlib.util
from pathlib import Path
import sys
from PIL import Image, ImageDraw, ImageFont

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ui_visual_preview", root / "ununknowntun-ui.py")
ui = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ui
spec.loader.exec_module(ui)
destination = Path(sys.argv[1])
if destination.exists():
    raise SystemExit("Preview output already exists; choose a new filename.")
font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 17)
rows = ui.render(ui.demo_tunnels(), page="doctor", demo=True, width=94).splitlines()
padding, line_height = 34, 26
width = round(font.getlength("M" * 94)) + padding * 2
height = len(rows) * line_height + padding * 2
image = Image.new("RGB", (width, height), "#f3f7fa")
draw = ImageDraw.Draw(image)
for index, line in enumerate(rows):
    color = "#294351"
    if all(c in "╭╮╰╯├┤─" for c in line):
        color = "#c6d4de"
    elif any(value in line for value in ("UNUNKNOWNTUN", "sik-dpi", "[ 3 Doctor ]", "IRAN IP", "ununknowntun >")):
        color = "#087f82"
    elif "SAMPLE DATA" in line:
        color = "#9e691c"
    elif "WAIT" in line or "TODO" in line or "companion" in line:
        color = "#75848e"
    draw.text((padding, padding + index * line_height), line, font=font, fill=color)
image.save(destination)
print("Actual sample terminal text rendered to " + str(destination))
