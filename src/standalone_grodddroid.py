from datetime import datetime
from Aion.utils.misc import restoreVirtualBoxSnapshot
import glob, os, subprocess, argparse

def logEvent(msg):
    return True
def loggingON():
    return True
def getTimestamp(includeDate=False):
    if includeDate:
        return "[%s]"%str(datetime.now())
    else:
        return "[%s]"%str(datetime.now()).split(" ")[1]

def prettyPrint(msg, mode="info"):
    """ Pretty prints a colored message. "info": Green, "error": Red, "warning": Yellow, "info2": Blue, "output": Magenta, "debug": White """
    if mode == "info":
        color = "32" # Green
    elif mode == "error":
        color = "31" # Red
    elif mode == "warning":
        color = "33" # Yellow
    elif mode == "info2":
        color = "34" # Blue
    elif mode == "output":
        color = "35" # Magenta
    elif mode == "debug":
        color = "37" # White
    else:
        color = "32"
    msg = "[*] %s. %s" % (msg, getTimestamp(includeDate=True))
    #print("\033[1;%sm%s\n%s\033[1;m" % (color, msg, '-'*len(msg))) # Print dashes under the message
    print("\033[1;%sm%s\033[1;m" % (color, msg))
    # Log the message if LOGGING is enabled
    if loggingON() and mode != "info":
        logEvent("%s: %s" % (getTimestamp(includeDate=True), msg))

def defineArguments():
    parser = argparse.ArgumentParser(prog="main_second.py", description="Emir's for Amelie's Laptop")
    parser.add_argument("--apkDir", required=True)
    parser.add_argument("--adbID", required=True)
    #parser.add_argument("--adbName", required=True)
    #parser.add_argument("--adbSnapshot", required=True)
    return parser


def main():
    argumentParser = defineArguments()
    arguments = argumentParser.parse_args()
    apkDir = arguments.apkDir
    adbID = arguments.adbID
    prettyPrint("Loading APK's from \"%s\"" % (apkDir))
    # Retrieve APKs
    APKs = glob.glob("%s/*.apk" % apkDir)
    if len(malAPKs) < 1:
        prettyPrint("Could not find any malicious APK's", "warning")
    else:
        existingAPKs = glob.glob("%s/*_grodddroid" % "/Users/emirdemirdag/Developer/PycharmProjects/thesis/new_input/*")
        for ff in existingAPKs:
            fileName = "%s.apk" % ff[:ff.find("_grodddroid")]
            head, tail = os.path.split(fileName)
            for fa in APKs: 
                if fa.find(tail) != -1:
                    APKs.remove(fa)
        prettyPrint("Successfully retrieved %s apk instances" % len(malAPKs))

    allAPKs = malAPKs
    while len(allAPKs) > 0:
        currentAPK = allAPKs.pop()
        branchExplorerDir = "" ## Add branch explorer directory here
        head, tail = os.path.split(currentAPK)
        parsedAPKName = "%s/%s" % (head, tail)
        groddDroidOut = parsedAPKName.replace(".apk", "_grodddroid")
        runType = "grodd"
        maxRuns = 10
        # start gordddroid
        main_cmd_call = ["python3", "-m", "branchexp.main", currentAPK, "--device", adbID, "--output-dir",
                         groddDroidOut, "--max-runs", "%s" % maxRuns, "--run-type", runType]
        prettyPrint("GroddDorid is running %s on %s" % (currentAPK, adbID), "info")
        success = subprocess.call(main_cmd_call, cwd=branchExplorerDir)
        if success == 0: prettyPrint("Run on %s terminated!!!!!!" % tail)

    prettyPrint("THIS NEW EXPERIMENT IS OVER. BYE")
if __name__ == "__main__":
    main()