import glob, subprocess, os

# malAPKs = glob.glob("/Users/emirdemirdag/Developer/PycharmProjects/thesis/new_input/*/*_grodddroid/run_*/apk")
malAPKs = glob.glob("%s/*_grodddroid/extractedDM_*_features.log" % "/Users/emirdemirdag/Developer/PycharmProjects/new_input/*")
count = 0
for app in malAPKs:
  head, tail = os.path.split(app)
  newDir = head.replace("/Developer/PycharmProjects/new_input/", "/Dropbox/GroddDroidFeatureVecs/")
  target = "%s/%s" % (newDir, tail)
  print app, target
  main_cmd_call = ["mkdir", newDir]
  main_cmd_call2 = ["cp", app, target]
  count += 1
  success = subprocess.call(main_cmd_call)
  success2 = subprocess.call(main_cmd_call2)

print count
