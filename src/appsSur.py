import glob, argparse


def defineArguments():
    parser = argparse.ArgumentParser(prog="appsSur.py", description="Shows how many apps survived")
    parser.add_argument("--resultDir", required=True)
    return parser

def countAppsAndRemoveDuplicates(logFiles):
    logCopies, uniqueApps = logFiles, []
    for app in logCopies:
        if app.count(".") > 1:
            logCopies.remove(app)
            continue
        appSplit = app.split("_test_itn")
        appName = appSplit[0].split("_filtered.log")[0].upper()
        if not appName in uniqueApps:
            uniqueApps.append(appName)
    return len(uniqueApps)
    
def main():
    argumentParser = defineArguments()
    arguments = argumentParser.parse_args()
    resultDir = arguments.resultDir
    file = open("./droidutanCountSurvived.txt", "w")

    for i in range(1,18):
      uniqueAppsMal, uniqueAppsGood = [], []
      malwareLogs = glob.glob("%s/run_%s/malware/*_filtered.log" % (resultDir, i))
      noOfMal = countAppsAndRemoveDuplicates(malwareLogs)
      file.write("There are %s malware logs in run %s\n" % (noOfMal, i))
      goodwareLogs = glob.glob("%s/run_%s/goodware/*_filtered.log" % (resultDir, i))
      noOfGood = countAppsAndRemoveDuplicates(goodwareLogs)
      file.write("There are %s goodware logs in run %s\n" % (noOfGood, i))
      file.write("Total logs of run %s is %s\n" % (i, noOfMal+noOfGood))

    file.close()
    print "THIS NEW EXPERIMENT IS OVER. BYE"
if __name__ == "__main__":
    main()
