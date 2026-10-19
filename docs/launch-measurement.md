# Launch measurement, separate from scanner behavior

Use a dedicated link on a maintainer-controlled website or redirect service for
future X release posts. Example campaign parameters:
`?utm_source=x&utm_medium=social&utm_campaign=sherlockscan_v030`.

Record aggregate campaign clicks, dated post engagement, and aggregate PyPI download
trends separately. Compare a defined pre-launch window with the following week.
Neither link clicks nor downloads establish unique users or completed installations;
a coincident increase is an association, not individual conversion attribution.

Do not introduce scanner/install telemetry. No tracking endpoint is configured by
this repository; the maintainer must select and configure the destination before
announcing the reviewed release. Keep analytics on the announcement link, with a
clear privacy notice and aggregate reporting. Publish subsequent release notes in
channels with demonstrated engagement and useful user feedback.
