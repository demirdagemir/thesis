import glob, argparse


def defineArguments():
    parser = argparse.ArgumentParser(prog="appsSur.py", description="Shows how many apps survived")
    parser.add_argument("--resultDir", required=True)
    return parser

def countFeatureVecs(logFiles):
    logCopies = logFiles
    return len(logCopies)
    
def main():
    argumentParser = defineArguments()
    arguments = argumentParser.parse_args()
    resultDir = arguments.resultDir
    file = open("./groddDroidCountMaxRun.txt", "w")
    uniqueAppsMal, uniqueAppsGood = [], []
    malwareLogs = glob.glob("%s/malware/*_grodddroid/run_9" % resultDir)
    noOfMal = countFeatureVecs(malwareLogs)
    file.write("There are %s malware logs in run\n" % noOfMal)
    goodwareLogs = glob.glob("%s/goodware/*_grodddroid/run_9" % resultDir)
    noOfGood = countFeatureVecs(goodwareLogs)
    file.write("There are %s goodware logs\n" % noOfGood)
    file.write("Total logs of run %s\n" % (noOfMal+noOfGood))

    file.close()
    print "THIS NEW EXPERIMENT IS OVER. BYE"
if __name__ == "__main__":
    main()
