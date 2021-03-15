# Web Scraper
This is a manga downloader as it has a ton of images and let me use beautiful soup plus a few other things.  
  
My different stages of building it are here  
  
![1-Initial](./Downloader-1-Initial.py) - My first draft, absolutely ugly and no real planning.  Everything is hard coded and shoved into a while loop.  
  
![2-Functions](./Downloader-2-Functions.py) - Converted to multiple functions, functions were still doing more than just 1 thing.  
  
![3-Threaded](./Downloader-3-Threaded.py) - Kept 2 as a base, no changes, and added in threading, why?  To learn.  
  
![4-Threaded-Tuple](./Downloader-4-Threaded_Tuple.py) - Started at 3, modified the worker function to push a tuple so that the download function could focus more on downloading instead of having to parse and hope everything was right.  
  
![5-Thread_Tuple-Split-Funcs](./Downloader-5-Threaded_Tuple-Split-Funcs.py) - Started at 4, split the previous massive download function into find_images and download_images functions.  Added docstrings for basic info.  
  
_in 5, remove the download function from find_images, just return the list, let the thread do a find and THEN download_  

  
### Thoughts
1.  So now, I'm not sure if calling download_images inside of find_images is the best thing or if I should break it out entirely.  Have find_images RETURN the list, then push that into download_images function so that they are slightly more independant?  
  
2.  I need a way to re-do the directory creation.  Instead of creating beforehand, maybe create on the fly so a folder bomb doesn't happen and if it fails and attempts to restart, it can get wonky about everything already existing.  
  
3.  Possibly take the list returned by find_images and push it into a seperate queue.  This way the downloading chapter(s) can be threaded and execute multiple at the same time(~ish) AND each chapter's images being download could be threaded to download multiple images at the same time(~ish).  OR make it do one chapter at a time and the images download be threaded.
