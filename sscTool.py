#!/usr/bin/env python2

import os, re, sys
import csv

# gui libs and resources
from PyQt4.QtCore import *
from PyQt4.QtGui import *
import ui_ssc_widget

MPC_FILE = 'mpc4.csv'

# use multiple inheritance to access both sets of attributes directly.
class SSCWidget(QTabWidget, ui_ssc_widget.Ui_TabWidget):

    def __init__(self, protocoldb, parent=None):
        super(SSCWidget, self).__init__(parent)
        # self.__text = unicode(text)
        self.__index = 0
        self._protocoldb = protocoldb
        self._count = 0
        self._listmodel = None
        self.setupUi(self)  # actually lays out the widget.

        # add signal-slot connections
        self.connect(self.sliderMaliciousness, SIGNAL("valueChanged(int)"),
                     self.updateUI)
        self.connect(self.sliderAdaptiveness, SIGNAL("valueChanged(int)"),
                     self.updateUI)
        self.connect(self.sliderFairness, SIGNAL("valueChanged(int)"),
                     self.updateUI)
        self.connect(self.sliderSecType, SIGNAL("valueChanged(int)"),
                     self.updateUI)
        self.connect(self.sliderCorruptedParties, SIGNAL("valueChanged(int)"),
                     self.updateUI)
        self.connect(self.sliderOnlineComm, SIGNAL("valueChanged(int)"),
                     self.updateUI)

        self.connect(self.cbMixedAdversary, SIGNAL("stateChanged(int)"),
                     self.updateUI)
        self.connect(self.cbComposable, SIGNAL("stateChanged(int)"),
                     self.updateUI)
        self.connect(self.cbSynchronous, SIGNAL("stateChanged(int)"),
                     self.updateUI)
        self.connect(self.cbTrustedSetup, SIGNAL("stateChanged(int)"),
                     self.updateUI)
        self.connect(self.cbBroadcast, SIGNAL("stateChanged(int)"),
                     self.updateUI)
        self.connect(self.cbConstantRounds, SIGNAL("stateChanged(int)"),
                     self.updateUI)
        self.connect(self.cbPreprocessing, SIGNAL("stateChanged(int)"),
                     self.updateUI)


        self.connect(self.radioExact, SIGNAL("toggled(bool)"), self.updateUI)
        self.connect(self.radioAtLeast, SIGNAL("toggled(bool)"), self.updateUI)

        self.listView.doubleClicked.connect(self.paperClicked)
        self.listView.clicked.connect(self.enableSetSliders)
        self.btnSetSliders.clicked.connect(self.setSliders)
        
        # LATER: MAC-specific stuff?
        self.updateUI()

    def enableSetSliders(self, index):
        self.btnSetSliders.setEnabled(True)

    def paperClicked(self, modelIndex):
        paperref = modelIndex.data().toString()
        annotation = ""
        rowind = 0;
        for row in self._protocoldb:
            if row['Protocol'] == paperref:
                annotation = row['Annotation']
                break
            rowind += 1
            
        popup = PopupDialog(paperref + ": " + annotation, self)
        popup.show()
        popup.raise_()

    # called on every gadget change, to update the paper list.
    def updateUI(self):
        results = self.matchProtocols()
        # wonder if this will delete it.
        self._listmodel = QStandardItemModel(self.listView)
        for protocol in results:
            self._listmodel.appendRow(QStandardItem(QString(protocol)))
        self.listView.setModel(self._listmodel)

        # disable slider button until something is clicked.
        self.btnSetSliders.setEnabled(False)


    def scaleCompare(self, a, b):
        if self.radioExact.isChecked(): return a == b
        else: return a >= b

    # set the sliders to match a protocol being viewed.
    def setSliders(self, protocolIndex):
        indexes = self.listView.selectedIndexes()
        if indexes == []:  # probably won't happen...
            return 
        paperref = indexes[0].data().toString()
        for row in self._protocoldb:
            if row['Protocol'] == paperref:
                break

        # wait! the environment checkboxes will already be set...
        #   but I might need to unset them.
        if int(row['Broadcast']) == 5: self.cbBroadcast.setChecked(False)
        else: self.cbBroadcast.setChecked(True)
        if int(row['Asynchro']) == 5: self.cbSynchronous.setChecked(False)
        else: self.cbSynchronous.setChecked(True)
        if int(row['Setup Assump']) == 5: self.cbTrustedSetup.setChecked(False)
        else: self.cbTrustedSetup.setChecked(True)
        if int(row['Comm Preproc']) == 5: self.cbPreprocessing.setChecked(False)
        else: self.cbPreprocessing.setChecked(True)

        if int(row['Rounds']) == 5: self.cbConstantRounds.setChecked(True)
        else: self.cbConstantRounds.setChecked(False)
        if int(row['Compos-ability']) == 5: self.cbComposable.setChecked(True)
        else: self.cbComposable.setChecked(False)
        if int(row['Mixed adv']) == 5: self.cbMixedAdversary.setChecked(True)
        else: self.cbMixedAdversary.setChecked(False)
        
        self.sliderAdaptiveness.setValue(int(row['Adaptivity']))
        self.sliderMaliciousness.setValue(int(row['Malicious-ness']))
        self.sliderCorruptedParties.setValue(int(row['# Corrupted']))
        self.sliderSecType.setValue(int(row['Security level']))
        self.sliderFairness.setValue(int(row['Fairness']))
        self.sliderOnlineComm.setValue(int(row['Complexity Level']))
        return

    # Return a list of protocols matching the sliders.
    def matchProtocols(self):
        # check impossibility independently (to catch myself)
        impossible = False
        # 1. No fairness if dishonest majority and malicious.
        if (self.sliderFairness.value() > 3 and
            self.sliderCorruptedParties.value() > 3 and
            self.sliderMaliciousness.value() > 2):
            impossible = True
        # 2. No more than n/3 corrupted parties if uncond and no bcast/error.
        if (self.sliderCorruptedParties.value() > 2 and
            self.sliderSecType.value() > 3 and
            not self.cbBroadcast.isChecked()):
            impossible = True
        # 3. UC dishonest majority malicious without setup assumption
        # .....without fairness? [GL02]
        #if (self.sliderMaliciousness.value() > 3 and 
        #    self.sliderCorruptedParties.value() > 3 and
        #    self.cbComposable.isChecked() and
        #    not self.cbTrustedSetup.isChecked()):
        #    impossible = True
        # 4. malicious dishonest majority with fairness
        if (self.sliderMaliciousness.value() > 3 and 
            self.sliderCorruptedParties.value() > 3 and
            self.sliderFairness.value() > 2):
            impossible = True

        results = []

        for row in self._protocoldb:
            match = True
            # slider features
            match &= self.scaleCompare(int(row['Malicious-ness']),
                                       self.sliderMaliciousness.value())
            match &= self.scaleCompare(int(row['# Corrupted']),
                                       self.sliderCorruptedParties.value())
            match &= self.scaleCompare(int(row['Adaptivity']),
                                       self.sliderAdaptiveness.value())
            match &= self.scaleCompare(int(row['Security level']),
                                       self.sliderSecType.value())
            match &= self.scaleCompare(int(row['Fairness']),
                                       self.sliderFairness.value())
            match &= self.scaleCompare(int(row['Complexity Level']),
                                       self.sliderOnlineComm.value())

            # security binary requirements
            match &= (not self.cbComposable.isChecked()) or \
                     int(row['Compos-ability']) == 5   # Pass04, GL02 are out.
            match &= (not self.cbMixedAdversary.isChecked()) or \
                     int(row['Mixed adv']) == 5
            # const round is an efficiency requirement: 
            match &= (not self.cbConstantRounds.isChecked()) or \
                     int(row['Rounds']) == 5

            # environment features aren't requirements: checked means 'available'
            match &= (self.cbBroadcast.isChecked() or
                      int(row['Broadcast']) == 5)
            match &= (self.cbSynchronous.isChecked() or
                      int(row['Asynchro']) == 5)
            match &= (self.cbTrustedSetup.isChecked() or 
                      int(row['Setup Assump']) == 5)
            match &= (self.cbPreprocessing.isChecked() or
                      int(row['Comm Preproc']) == 5)
            
            if match: results.append(row['Protocol'])

        if (results == []):
            self.lblProtocolsFound.setText(QString(""))
        else:
            self.lblProtocolsFound.setStyleSheet("QLabel { color : green; }")
            self.lblProtocolsFound.setText(QString("Protocols found:"))
        if (impossible):
            self.lblProtocolsFound.setStyleSheet("QLabel { color : red; }")
            self.lblProtocolsFound.setText(QString("Known Impossible"))

        return results

# end class

##############################
# class for popup info dialogs
##############################
class PopupDialog(QDialog):
    def __init__(self, textfield, parent=None):
        super(PopupDialog, self).__init__(parent)
        self.textView = QPlainTextEdit(self)
        self.textView.setGeometry(QRect(20, 20, 260, 160))
        #self.textView.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.textView.setObjectName("textView")
        # set title to paper name and show abstract
        self.textView.setPlainText(textfield)
        self.textView.setReadOnly(True)
        
        self.resize(300,200)
    
    def showEvent(self, event):
        geom = self.frameGeometry()
        geom.moveCenter(QCursor.pos())
        self.setGeometry(geom)
        super(PopupDialog, self).showEvent(event) # no idea.
    
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.hide()
            event.accept()
        else:
            super(PopupDialog, self).keyPressEvent(event)

######
# main
######
def main():
    csvdb = []
    # make sure it can find the csv file from anywhere.
    os.path.join(os.path.dirname(sys.executable))
    with open(MPC_FILE, 'rb') as csvfile:
        csvreader = csv.DictReader(csvfile, dialect='excel')
        print "papers loaded:"
        for row in csvreader:
            print row['Protocol'], ", ",
            csvdb.append(row)
    print
    app = QApplication(sys.argv)
    sscWidget = SSCWidget(csvdb)
    sscWidget.show()
    app.exec_()


main()


