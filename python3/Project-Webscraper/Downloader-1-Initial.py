#!/usr/bin/python3
import requests
import bs4
import os

BASEURL = 'https://ww2.read7deadlysins.com/chapter/nanatsu-no-taizai-chapter-'

os.makedirs('seven', exist_ok=True)  # Create the base directory

chapter = 1

while chapter < 304:  # 303 was the highest chapter at the time

    # formatted_chapter = "%03d" % chapter  # Formats to triple digits
    formatted_chapter = '{:03}'.format(chapter)

    os.makedirs(os.path.join('seven', formatted_chapter))  # Creates the subdirectory for each chapter

    # Download the page
    print('Downloading page {}...'.format(BASEURL + formatted_chapter))
    res = requests.get(BASEURL + formatted_chapter)
    res.raise_for_status()

    soup = bs4.BeautifulSoup(res.text, features="html.parser")

    all_images = soup.findAll("img", {"class": "pages__img"})

    if all_images == []:
        print('Could not find any images')
    else:
        try:
            for i in all_images:
                image_url = i.get('src')  # Alternative is i['src']
                # Download the image
                # print('Downloading image %s...' % image_url)
                print('Downloading Chapter {} - Image {} ...'.format(formatted_chapter, os.path.basename(image_url)))
                # res = requests.get(image_url)
                res = requests.get(image_url,
                                   stream=True)  # stream=True prevents downloading the entire image into memory first
                res.raise_for_status()

                # imageFile = open(os.path.join('seven', os.path.basename(image_url)), 'wb')

                # requests needs to write in chunks, so we use iter_content to do it in 100k byte chunks
                with open(os.path.join('seven', formatted_chapter, os.path.basename(image_url)), 'wb') as imageFile:
                    for chunk in res.iter_content(100000):
                        imageFile.write(chunk)
                # imageFile.close()

        except Exception as ex:
            # Skip this image
            print("Hit the exception...", type(ex), ex)
            continue

    chapter += 1

print('All done.')
