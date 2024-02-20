import requests
from lxml import etree
from datetime import datetime
import json
import logging
import os

# Set up basic logging to the standard output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_and_format_date(input_string):
    date_string = input_string.replace("Submitted ", "").replace(" by", "")
    day_part = date_string.split(" ")[1]
    day = ''.join(filter(str.isdigit, day_part))
    date_string_cleaned = date_string.replace(day_part, day)
    date_object = datetime.strptime(date_string_cleaned, "%b %d %Y %I:%M %p")
    return date_object.strftime("%Y-%m-%d %H:%M:%S")

def load_existing_data(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return []

def save_to_json(phishing_urls, filename="phishing_urls.json"):
    with open(filename, 'w') as f:
        json.dump(phishing_urls, f, indent=4)

def fetch_phishing_urls(start_id, end_date, filename="phishtank_data/phishing_urls.json"):
    existing_data = load_existing_data(filename)
    existing_ids = {item['id'] for item in existing_data}
    phishing_urls = existing_data

    for phish_id in range(start_id, 0, -1):
        if phish_id in existing_ids:
            logging.info(f"Skipping already crawled ID: {phish_id}")
            continue

        url = f"https://phishtank.org/phish_detail.php?phish_id={phish_id}"
        logging.info(f"Prcessing {url}")
        response = requests.get(url)
        if response.status_code != 200:
            logging.warning(f"Failed to retrieve page for ID {phish_id}. Status code: {response.status_code}")
            continue

        tree = etree.HTML(response.text)
        try:
            url_details = {
                'id': phish_id,
                'url': tree.xpath('//*[@id="widecol"]/div/div[3]/span/b')[0].text,
                # 'verified': tree.xpath('//table[@class="phish-detail"]//h3')[0].text.strip(': ').lower(),
                'online': tree.xpath('//*[@id="widecol"]/div/h2/span')[0].text.split(' ')[-1].strip().lower(),
                'added_time': parse_and_format_date(tree.xpath('//*[@id="widecol"]/div/div[2]/span/text()[1]')[0].strip())
            }
        except IndexError as e:
            logging.error(f"Error parsing data for ID {phish_id}: {e}")
            continue

        added_time = datetime.strptime(url_details['added_time'], "%Y-%m-%d %H:%M:%S")
        if added_time < end_date:
            logging.info(f"Reached phishing URLs before {end_date}. Stopping crawl.")
            break

        logging.info(f"Fetched URL for ID {phish_id}: {url_details['url']}")
        phishing_urls.append(url_details)

        if phish_id%10==0:
            save_to_json(phishing_urls, filename)
    save_to_json(phishing_urls, filename)

end_date = datetime(2023, 1, 1)  # Target end date
start_id = 8460076  # Starting phishing ID

# Fetch phishing URLs and update the saved file
fetch_phishing_urls(start_id, end_date)
