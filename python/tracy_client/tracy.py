# -*- coding: utf-8 -*-

from typing import Optional, Union

from tracy_client.TracyClientBindings import (
    is_enabled,
    program_name,
    thread_name,
    app_info,
    ColorType,
    PlotFormatType,
    frame_mark,
    frame_mark_start,
    frame_mark_end,
    frame_image,
    alloc,
    free,
    message,
    plot,
    _plot_config,
)
from tracy_client.scoped import (
    Color,
    ScopedZone,
    ScopedFrame,
    ScopedZoneDecorator,
    ScopedFrameDecorator,
)

PlotType = Union[int, PlotFormatType]


def plot_config(
    name: str, type: PlotType, step: bool = False, flip: bool = False, color: Color = 0
) -> Optional[int]:
    return _plot_config(name, int(type), step, flip, int(color))
