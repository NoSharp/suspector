import sys
import os
import subprocess
import shutil
dir_path = sys.argv[1]
out_path = sys.argv[2]

for file_path in os.listdir(dir_path):
  driver_path = os.path.join(dir_path, file_path)
  if os.path.isfile(driver_path):
    result = subprocess.Popen("./suspector.exe " + driver_path)
    text = result.communicate()[0]
    return_code = result.returncode
    if return_code == 1:
      shutil.copy(driver_path, out_path)