<img src="https://circleci.com/gh/plotly/le-bot.svg?style=shield&circle-token=b125d59fd644e3d5eb1d17562c7bc817425861aa"></br>

# le-bot

<p align="center">
<img src="https://vectr.com/iloveorange/canJ3TwIm.png?width=642.52&height=310&select=canJ3TwImpage0">
</p>

Bot that creates/distributes/updates certificates for a supplied subdomain and a known domain.
To be used on a Google Cloud machine and Let's Encrypt's bash client [dehydrated.sh](https://github.com/lukas2511/dehydrated).

# Requirements
Python 2.7 environment

Let's Encrypt shell client dehydrated

```bash
curl -sL https://github.com/lukas2511/dehydrated/archive/v0.4.0.tar.gz | tar xz
```

Assuming your domain is `your-domain.com` that is under `your-zone` zone in your Google Cloud DNS records,

- You must be authenticated with `gcloud`, run `gcloud auth login`.

- Set the correct Google Cloud project `gcloud config set project $GCLOUD_PROJECT_NAME`.

- Your `gcloud` account must have access to modify DNS entries of the aforementioned Google Cloud zone of that project.

# How to use

### Setup

In a new directory
```bash
git clone https://github.com/alexandresobolevski/le-bot.git
cd le-bot
pip install -r requirements.txt
```

- Duplicate the file `credentials-example.sh` as `credentials.sh` and modify the entries  `ZONE_NAME` and `DNS_DOMAIN` to your Google Cloud DNS zone name and domain respectively i.e.
```
ZONE_NAME="your-zone"
DNS_DOMAIN="your-domain.com"
```

### Run

- Start the bot server:
```
python le-server.py 9090
```

- Post a request to the server to obtain the certificate as shown in the screenshot below,

<p align="center">
    <img src="http://i.imgur.com/C65sI6h.png)">
</p>

- Write the response from the bot (as seen above) to files (`cert.pem` and `key.pem`) and save the received `subdomain`. Your certificates will work for a server hosted on `subdomain.your-domain.com:${port}`. Use created files (cert and key) when starting an HTTPS server.

### Test

- Duplicate (if not yet done) `credentials-example.sh` as `credentials.sh` and modify the entries  `ZONE_NAME` and `DNS_DOMAIN` to your Google Cloud DNS zone name and domain respectively as well as the Plotly credentials (`PLOTLY_API_KEY`, `PLOTLY_USERNAME` and `PLOTLY_ACCESS_KEY`) i.e.

- Run the tests.
```
source credentials.sh && python test.py
```
