# Simple OSINT Crawler

This simple Python script is designed to crawl a given website (and optionally follow links within it) to extract useful information for OSINT (Open Source Intelligence) purposes. The crawler looks for things like email addresses, potential passwords, OSINT flags (such as IP addresses, .onion links, cryptocurrency addresses), alerts based on defined keywords, and links to PDF files.

## Features

* **Website Crawling:** Visits the specified URL and analyzes its content.
* **Email Extraction:** Retrieves all found email addresses.
* **Potential Password Detection:** Identifies strings that might be passwords based on certain patterns.
* **OSINT Flag Detection:** Finds common patterns like IPv4 and IPv6 addresses, Tor network links (.onion), Bitcoin and Ethereum addresses, and potential login forms.
* **Keyword Alerts:** Searches for defined keywords and displays snippets of text where they are found.
* **PDF Link Detection:** Identifies and reports links to PDF files found on the page.
* **Crawl Depth Limiter:** Option to set the maximum depth for following links within the domain.
* **Log File Output:** All found information is saved to a text file with the source URL.

## How to Use

1.  **Download the script:** You can download the `crawler.py` file from this repository.
2.  **Run the script:** Open your terminal or command prompt, navigate to the folder where you saved `crawler.py`, and run it using Python:
    ```bash
    python crawler.py
    ```
3.  **Enter the URL:** The script will ask for the starting URL to crawl. Enter it and press Enter.
4.  **Check the log file:** After the script finishes, it will create a file named `yourdomain_crawl_log.txt` in the same folder, containing all the extracted information.

## Options

* **Crawl Depth:** By default, the script only crawls the specified URL and links directly on that page (depth 1). You can modify the `max_depth` value in the `crawl_website` function in the code to change the crawling depth.

## Dependencies

* `requests`: For fetching website content.
* `beautifulsoup4` (`bs4`): For parsing HTML code.
* `urllib.parse`: For parsing and joining URLs.

You can install these dependencies using pip:

```bash
pip install requests beautifulsoup4


**Regarding the `crawler.py` file for download:**

As mentioned before, you simply need to include the `crawler.py` file in the main directory of your GitHub repository. GitHub will automatically handle the ability for users to download it when they browse your repository. They can either:

1.  **Download directly:** By clicking on the `crawler.py` file in the repository view and then selecting "Download."
2.  **Clone the repository:** By using the `git clone [URL_of_your_repository]` command, which will download all the files, including `crawler.py`.
3.  **Download as ZIP:** GitHub provides an option to download the entire repository as a ZIP archive.

You don't need to create a separate downloadable file. Just ensure `crawler.py` is part of your repository.

**Next Steps:**

1.  Create a file named `README.md` in the root folder of your project.
2.  Copy and paste the English content above into this file. Feel free to adjust the "Author" and "License" sections.
3.  Make sure your `crawler.py` file is also in the same root folder.
4.  Commit these files to your Git repository and push the changes to GitHub.

After doing this, anyone visiting your GitHub repository will see the description in the `README.md` file, and they will be able to download the `crawler.py` script.
