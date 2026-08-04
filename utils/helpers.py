def normalize_url(url):

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def clean_domain(url):

    url = (
        url.replace("https://", "")
           .replace("http://", "")
           .replace("www.", "")
    )

    return url.split("/")[0]
