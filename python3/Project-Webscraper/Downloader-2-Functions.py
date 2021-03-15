#!/usr/bin/python3
import requests
import bs4
import os

HOMEPAGE = 'https://ww2.read7deadlysins.com'
BASEURL = 'https://ww2.read7deadlysins.com/chapter/nanatsu-no-taizai-chapter-'
MANGANAME = 'Seven_Deadly_Sins'


def find_latest(HOMEPAGE):
    try:
        res = requests.get(HOMEPAGE)
        res.raise_for_status()

        soup = bs4.BeautifulSoup(res.text, features="html.parser")

        # Takes me into the tbody class, then a class, then the href key inside the dict
        latest_chap = soup.tbody.a['href'].strip('/').split('-')[-1]

        return int(latest_chap)
    except Exception as ex:
        print("Caught", ex, "as", type(ex))


def gen_pages(BASEURL, latest, chapter=1):
    pages = []
    chapters = []

    for i in range(chapter, latest+1):
        formatted_chapter = f'{i:03}'
        # print(BASEURL+formatted_chapter)
        pages.append(BASEURL+formatted_chapter)
        chapters.append(formatted_chapter)

    return chapters, pages


def dir_create(chapters):
    os.makedirs(MANGANAME, exist_ok=True)  # Create the base directory
    for chapter in chapters:
        os.makedirs(os.path.join(MANGANAME, chapter))  # Creates the subdirectory for each chapter


def download_chapter(chapters, pages):
    # for page in pages:
    for page in list(zip(chapters, pages)):
        print(f'Downloading Chapter {page[0]}...')
        res = requests.get(page[1])
        res.raise_for_status()

        soup = bs4.BeautifulSoup(res.text, features="html.parser")

        all_images = soup.findAll("img", {"class": "pages__img"})

        if not all_images:
            print('Could not find any images')
        else:
            try:
                for i in all_images:
                    image_url = i.get('src')  # Alternative is i['src'] # Returns URL of just the image
                    # stream=True prevents downloading the entire image into memory first
                    res = requests.get(image_url, stream=True)
                    res.raise_for_status()
                    with open(os.path.join(MANGANAME, page[0], os.path.basename(image_url)), 'wb') as image_file:
                        for chunk in res.iter_content(100000):
                            image_file.write(chunk)

            except Exception as ex:
                # Skip this image
                print("Hit the exception...", type(ex), ex)
                continue


def main():
    print("Finding latest chapter...")
    latest = find_latest(HOMEPAGE)
    print("Found:", latest)
    print("\nGenerating a list of all chapters and pages they are at...")
    chapters, pages = gen_pages(BASEURL, latest)
    print("\nCreating all directories for the base and chapters...")
    dir_create(chapters)
    print("\nBeginning download of all chapters...")
    download_chapter(chapters, pages)
    print("\n\nAll done")


if __name__ == "__main__":
    main()
