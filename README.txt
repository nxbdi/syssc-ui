SSC-UI BUILD/RUN NOTES
(Google code hosted version)

This UI was written in Python 2.7 using the PyQT library. The UI code must first be built by running:

$ pyuic4 ssc_widget.ui > ui_ssc_widget.py

Then the program can be started by running the 'sscTool.py' script directly. The protocol database 'mpc_v5.csv' must be in the same directory.

September 4, 2014

