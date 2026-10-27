"""Coordinate-distance helpers for the SUMO network's metre-based plane."""
import math


def distance_m(point_a, point_b):
    dx = float(point_a["x"]) - float(point_b["x"])
    dy = float(point_a["y"]) - float(point_b["y"])
    return math.hypot(dx, dy)


def within_range(point_a, point_b, range_m):
    if float(range_m) < 0:
        raise ValueError("range_m must be non-negative")
    return distance_m(point_a, point_b) <= float(range_m)
