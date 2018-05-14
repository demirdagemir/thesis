#!/usr/bin/python

# Aion imports
from Aion.utils.graphics import *
from Aion.utils.misc import *
# Python imports
import os, subprocess, signal
from multiprocessing import Process


class GroddDroidAnalysis(Process):
    """
    Represents a GroddDroid-driven test of an APK
    """

    def __init__(self, pID, pName, pVM, pTarget, pSt=""):
        """
        Initialize the test
        :param pID: Used to identify the process
        :type pID: int
        :param pName: A unique name given to a proces
        :type pName: str
        :param pVM: The Genymotion AVD name to run the test on
        :type pVM: str
        :param pTarget: The path to the APK under test
        :type pTarget: str
        :param pSt: The snapshot of the AVD in case restoring is needed
        :type pSt: str
        :param pDuration: The duration of the Droidutan test in seconds (default: 60s)
        :type pDuration: int
        """
        Process.__init__(self, name=pName)
        self.processID = pID
        self.processName = pName
        self.processVM = pVM
        self.processTarget = pTarget
        self.processSnapshot = pSt

    def run(self):
        """
        Runs the GroidDroid
        """
        prettyPrint("%s is running on %s" % (
        self.processTarget, self.processVM), "success")
        try:
            # Step 1. Notify beginning
            if verboseON():
                prettyPrint(
                    "Analyzing APK: \"%s\"" % self.processTarget,
                    "debug")
            if self.processTarget.find(".apk") == -1:
                prettyPrint(
                    "Could not retrieve an APK to analyze. Skipping",
                    "warning")
                return False
            # Step 2. Get the Ip address assigned to the AVD
            getAVDIPCmd = ["VBoxManage", "guestproperty",
                           "enumerate", self.processVM]
            avdIP = ""
            result = subprocess.Popen(getAVDIPCmd,
                                      stderr=subprocess.STDOUT,
                                      stdout=subprocess.PIPE).communicate()[
                0].replace(' ', '')
            if result.lower().find("error") != -1:
                prettyPrint(
                    "Unable to retrieve the IP address of the AVD",
                    "error")
                print
                result
                return False
            index = result.find(
                "androvm_ip_management,value:") + len(
                "androvm_ip_management,value:")
            while result[index] != ',':
                avdIP += result[index]
                index += 1
            adbID = "%s:5555" % avdIP

            ############################################
            # Step 3 Unleash GroddDroid
            ###########################################

            # 3.1 Change the Output Directory For the GroddDroid
            branchExplorerDir = "" # insert branch exp here
            head, tail = os.path.split(self.processTarget)
            parsedAPKName = "%s/%s" % (head, tail)
            groddDroidOut = parsedAPKName.replace(".apk",
                                                  "_grodddroid")
            runType = "grodd"
            maxRuns = 10
            # start gordddroid
            main_cmd_call = ["python3", "-m",
                             "branchexp.main",
                             self.processTarget, "--device",
                             adbID, "--output-dir",
                             groddDroidOut, "--max-runs",
                             "%s" % maxRuns, "--run-type",
                             runType]
            prettyPrint("Command is running %s on %s" % (
            main_cmd_call, self.processVM), "info")
            success = subprocess.call(main_cmd_call,
                                      cwd=branchExplorerDir)
            if success == 0: prettyPrint(
                "Run on %s terminated!!!!!!" % tail)
        except Exception as e:
            prettyPrintError(e)

        return True

    def stop(self):
        """
        Stops this analysis process
        """
        try:
            prettyPrint(
                "Stopping the analysis process \"%s\" on \"%s\"" % (
                self.processName, self.processVM),
                "warning")
            os.kill(os.getpid(), signal.SIGTERM)

        except Exception as e:
            prettyPrintError(e)

        return True
