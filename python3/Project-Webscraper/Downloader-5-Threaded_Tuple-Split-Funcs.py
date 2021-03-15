#!/usr/bin/python3
import requests
import bs4
import os
import time
from queue import Queue
from threading import Thread
from threading import current_thread

# https://code.tutsplus.com/articles/introduction-to-parallel-and-concurrent-programming-in-python--cms-28612

HOMEPAGE = 'https://ww2.read7deadlysins.com'
BASEURL = 'https://ww2.read7deadlysins.com/chapter/nanatsu-no-taizai-chapter-'
MANGANAME = 'Seven_Deadly_Sins-Test'

NUM_WORKERS = 4
task_queue = Queue()

# TODO: Add try/except on dir create to allow overwriting or prevent.  Or prompt?
# TODO: Maybe move the results of find_image() into a separate queue for threading?


def worker():
    """ Constantly check the queue for addresses """
    while True:
        address_tuple = task_queue.get()
        print(f"PID: {os.getpid()}, Thread Name: {current_thread().name}", end='\t')  # Debug code to show PID & Thread-ID
        find_images(address_tuple)

        # Mark the processed task as done
        task_queue.task_done()


def find_latest(HOMEPAGE):
    """ Finds the latest chapter for download by parsing the web page"""
    try:
        res = requests.get(HOMEPAGE)
        res.raise_for_status()

        soup = bs4.BeautifulSoup(res.text, features="html.parser")

        # Takes me into the tbody class, then a class, then the href key inside the dict that exists in a class.
        latest_chap = soup.tbody.a['href'].strip('/').split('-')[-1]

        return int(latest_chap)
    except Exception as ex:
        print("Caught", ex, "as", type(ex))


def gen_pages(BASEURL, latest, chapter=1):
    """
    Generates a list from the starting chapter specified (defaults to chapter=1)
    Then runs a range from Starting Chapter to Latest chapter.
    Returns a list of 3 digit formatted chapters and the links to each of those pages.
    """
    pages = []
    chapters = []

    for i in range(chapter, latest+1):
        formatted_chapter = f'{i:03}'       # Requires pretty formatting to reach chapters
        pages.append(BASEURL+formatted_chapter)
        chapters.append(formatted_chapter)

    return chapters, pages


def dir_create(chapters):
    """Creates the base directory and then from the range chapter list, creates all subdirectories"""
    os.makedirs(MANGANAME, exist_ok=True)  # Create the base directory
    for chapter in chapters:
        os.makedirs(os.path.join(MANGANAME, chapter))  # Creates the subdirectory for each chapter


def download_images(chapter, all_images):
    """Download images from full URLs provided in a list by the find_images function"""
    for i in all_images:
        image_url = i.get('src')  # Alternative is i['src'] # Returns URL of just the image
        # stream=True prevents downloading the entire image into memory first
        res = requests.get(image_url, stream=True)
        res.raise_for_status()
        with open(os.path.join(MANGANAME, chapter, os.path.basename(image_url)), 'wb') as image_file:
            for chunk in res.iter_content(100000):
                image_file.write(chunk)


def find_images(address_tuple):
    """Parses each chapter page for all images and if found pushes straight to download"""
    chapter = address_tuple[0]
    address = address_tuple[1]
    print(f'Locating Chapter {chapter} Images...')
    res = requests.get(address)
    res.raise_for_status()

    soup = bs4.BeautifulSoup(res.text, features="html.parser")

    all_images = soup.findAll("img", {"class": "pages__img"})

    if not all_images:
        print('Could not find any images')
    else:
        try:
            download_images(chapter, all_images)

        # Skip the bad image / missing images
        except Exception as ex:
            print("Hit the exception...", type(ex), ex)


def main():
    start_time = time.time()
    print("Finding latest chapter...", end='')
    latest = find_latest(HOMEPAGE)
    print("Found:", latest)
    print("\nGenerating a list of all chapters and pages they are at...")
    chapters, pages = gen_pages(BASEURL, latest)
    print("\nCreating all directories for the base and chapters...")
    dir_create(chapters)
    print("\nBeginning download of all chapters...")

    # Create the worker threads
    threads = [Thread(target=worker) for _ in range(NUM_WORKERS)]

    # Add the websites to the task queue
    [task_queue.put(item) for item in list(zip(chapters, pages))]   # Creates a list of tuples (Chapter #, URL)

    # Start all the workers
    [thread.start() for thread in threads]

    # Wait for all the tasks in the queue to be processed
    task_queue.join()

    print("\n\nAll done")
    end_time = time.time()
    print(f"Time for Threading: {end_time - start_time}")


if __name__ == "__main__":
    main()
