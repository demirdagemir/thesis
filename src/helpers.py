from Aion.utils.data import getADBPath
import subprocess

def dumpLogCat(apkTarget):
    # Aion/shared/DroidutanTest.py
    # Define frequently-used commands
    # TODO: Refactor  adbID
    adbID = "192.168.58.101:5555"
    adbPath = getADBPath()
    dumpLogcatCmd = [adbPath, "-s", adbID, "logcat", "-d"]
    clearLogcatCmd = [adbPath, "-s", adbID, "-c"]

    # 5. Dump the system log to file
    logcatFile = open(apkTarget.replace(".apk", ".log"), "w")
    prettyPrint("Dumping logcat")
    subprocess.Popen(dumpLogcatCmd, stderr=subprocess.STDOUT, stdout=logcatFile).communicate()[0]
    logcatFile.close()
