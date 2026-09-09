# BC Sentinel v0.2.0-beta FIX1

Fixes a Windows/Qt runtime crash caused by a method-name collision.

`QMainWindow` inherits `QPaintDevice.metric(PaintDeviceMetric)`. BC Sentinel's
dashboard had introduced a helper also named `metric(...)` for statistic cards.
Qt invokes `metric()` internally while painting, passing a `PaintDeviceMetric`
enum. The custom helper then attempted `title.upper()`, causing:

`AttributeError: 'PaintDeviceMetric' object has no attribute 'upper'`

The dashboard helper is now named `metric_card()` and all references were updated.

No scanner, ransomware, ETW, quarantine, process-monitor or threat-scoring logic
was changed in this fix.
