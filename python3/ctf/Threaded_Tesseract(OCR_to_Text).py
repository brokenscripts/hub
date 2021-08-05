import os
import glob
import concurrent.futures
import time
import pytesseract
import cv2
import re

"""
https://appliedmachinelearning.blog/2018/06/30/performing-ocr-by-running-parallel-instances-of-tesseract-4-0-python/
Step 1: pip install pytesseract opencv-python
Step 2: apt install ffmpeg tesseract-ocr
Step 3: ffmpeg -i FILENAME.mpg -r 1/1 $FILENAME%03d.jpg
     This reads every SINGLE frame and converts to jpg for parsing with PyTesseract (OCR)
"""
 
def ocr(img_path):
    out_dir = "/root/Downloads/ocr_results/"
    img = cv2.imread(img_path)
    text = pytesseract.image_to_string(img,lang='eng',config='--psm 6')
    out_file = re.sub(".jpg",".txt",img_path.split("/")[-1])
    out_path = out_dir + out_file
    fd = open(out_path,"w")
    fd.write("%s" %text)
    return out_file

os.environ['OMP_THREAD_LIMIT'] = '1'
def main():
    path = "/root/Downloads/nsa"
    if os.path.isdir(path) == 1:
        out_dir = "/root/Downloads/ocr_results"
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
 
        with concurrent.futures.ProcessPoolExecutor(max_workers=4) as executor:
            image_list = glob.glob(path+"/*.jpg")
            for img_path,out_file in zip(image_list,executor.map(ocr,image_list)):
                print(img_path.split("/")[-1],',',out_file,', processed')
 
if __name__ == '__main__':
    start = time.time()
    main()
    end = time.time()
    print(end-start)
