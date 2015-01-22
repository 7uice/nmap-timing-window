# nmap-timing-window
A script that allows a user to specify a start and a stop time for nmap. This is intended for overnight scanning. If the scan does not finish in one night, it will idle until the next night and then continue. When it's done, all outputs will be combined into a MSF-importable .xml file, along with .nmap and .gnmap formats.
